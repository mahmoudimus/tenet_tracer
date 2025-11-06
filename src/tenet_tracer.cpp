// tenet_tracer_tool.cpp
// Build with Pin 3.31 (intel64), C++11, /MD. Requires your ImageManager.h and Logger.h.

#include <array>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <utility>
#include <map>
#include <memory>
#include <unordered_map>
#include <set>
#include <sstream>

#include "pin.H"

#if defined(_WIN32) || defined(_WIN64)
namespace WINDOWS
{
#include <windows.h>
}
#endif

#include "ImageManager.h"
#include "Logger.h"

#include "PathUtils.h"

#ifdef __i386__
#define PC "eip"
#else
#define PC "rip"
#endif

#if defined(USE_SQLITE3)
#include "SqliteLogHandler.h"
// Global SQLite database for trace logging
sqlite3* g_trace_db = nullptr;
// Global queue for all trace entries
std::vector<tenet_tracer::GlobalTraceEntry> tenet_tracer::g_trace_queue;
PIN_LOCK tenet_tracer::g_trace_queue_lock;
PIN_THREAD_UID tenet_tracer::g_flush_thread_uid = 0;
bool tenet_tracer::g_flush_thread_should_exit = false;
// Global shared state to avoid function-local statics in SqliteLogHandler
tenet_tracer::SqliteSharedState tenet_tracer::g_sqlite_state;
#endif
std::unique_ptr<tenet_tracer::Logger> meta_logger;

// -----------------------------------------------------
// Tool arguments (knobs)

static KNOB<std::string> KnobModuleWhitelist(
    KNOB_MODE_APPEND, "pintool", "w", "",
    "Add a module to the whitelist. If none is specified, every module is white-listed. Example: calc.exe");

static KNOB<std::string> KnobOutputFilePrefix(
    KNOB_MODE_WRITEONCE, "pintool", "o", "trace",
    "Prefix of the output file. If none is specified, 'trace' is used.");

static KNOB<std::string> KnobImageBase(
    KNOB_MODE_APPEND, "pintool", "i", "",
    "Image base address remapping. Syntax: ImageName:0xBase. Example: -i WowT.exe:0x140000000");

// Name of a DLL to trace exclusively; tracing starts when it is loaded.
static KNOB<std::string> KnobTraceModule(
    KNOB_MODE_WRITEONCE, "pintool", "m", "",
    "Name of the module (DLL) to trace. Tracing starts when this module loads.");

// -----------------------------------------------------
// Misc / util

// On x64 Windows ADDRINT fits in unsigned long long.
static inline unsigned long long asU64(ADDRINT x)
{
    return static_cast<unsigned long long>(x);
}

// -----------------------------------------------------
// Per-thread data (lock-free logging per thread)

struct alignas(64) ThreadData
{
    ADDRINT m_cpu_pc{0};
    std::array<ADDRINT, REG_GR_LAST + 1> m_cpu{}; // zero-inited

    ADDRINT mem_w_addr{0}, mem_w_size{0};
    ADDRINT mem_r_addr{0}, mem_r_size{0};
    ADDRINT mem_r2_addr{0}, mem_r2_size{0};

    std::unordered_map<std::string, std::unique_ptr<tenet_tracer::Logger>> m_image_logs;
    alignas(64) char m_scratch[1024]{};

    // Optional utility if you want a per-image+tid file under a dir
    tenet_tracer::Logger& GetOrCreateLogger(const std::string& imageBaseName,
                                            const std::string& logDir,
                                            int pid,
                                            THREADID tid)
    {
        if (m_image_logs.empty()) m_image_logs.reserve(32);
        std::string key(imageBaseName);
        auto it = m_image_logs.find(key);
        if (it != m_image_logs.end()) return *(it->second);

        std::ostringstream path;
        path << logDir << PathUtils::PATH_SEP
            << PathUtils::SanitizeFilename(imageBaseName)
            << "_pid" << pid << "_T" << tid << ".log";

        PathUtils::EnsureDirectoryExists(path.str());
        auto logger = tenet_tracer::LoggerBuilder()
                      .addFileHandler(path.str(), 10 * 1024 * 1024, false)
                      .build();
        logger->setThreadId(static_cast<unsigned>(tid));
        auto* raw = logger.get();
        m_image_logs.emplace(std::move(key), std::move(logger));
        return *raw;
    }

    void CloseAllLogs()
    {
        for (auto& kv : m_image_logs)
        {
            if (kv.second) kv.second->close();
        }
        m_image_logs.clear();
    }
};

// -----------------------------------------------------
// Tool context

class ToolContext
{
public:
    ToolContext()
        : m_tracing_started(false), image_base_(0)
    {
        if (meta_logger) meta_logger->info("Initializing ToolContext before creating ImageManager!");

        PIN_InitLock(&m_loaded_images_lock);
        PIN_InitLock(&m_thread_lock);
        if (meta_logger) meta_logger->info("Initializing ToolContext before getting the thread data key!");

        m_tls_key = PIN_CreateThreadDataKey(nullptr);
        if (meta_logger) meta_logger->info("Initializing ToolContext before creating ImageManager!");
        m_images = std::make_unique<ImageManager>();
        if (meta_logger) meta_logger->info("Initializing ToolContext AFTER! creating ImageManager!");
    }

    // API
    ADDRINT image_base() const noexcept { return image_base_; }

    ThreadData* GetThreadLocalData(THREADID tid) const noexcept
    {
        return static_cast<ThreadData*>(PIN_GetThreadData(m_tls_key, tid));
    }

    void SetThreadLocalData(THREADID tid, ThreadData* data) const noexcept
    {
        PIN_SetThreadData(m_tls_key, data, tid);
    }

    // Binary search for the image base owning 'addr'. Vector must be sorted by low_.
    ADDRINT FindImageBaseForAddress(ADDRINT addr) const noexcept
    {
        LoadedImage probe("probe", addr, 0, 0);
        auto it = std::upper_bound(m_loaded_images.begin(), m_loaded_images.end(), probe);
        if (it == m_loaded_images.begin()) return 0;
        --it;
        return (addr >= it->low_ && addr < it->high_) ? it->low_ : 0;
    }

    void RegisterLoadedImage(ADDRINT low, ADDRINT high, std::string baseName, ADDRINT desired = 0)
    {
        PIN_GetLock(&m_loaded_images_lock, 0);
        m_loaded_images.emplace_back(std::move(baseName), low, high, desired);
        std::inplace_merge(m_loaded_images.begin(),
                           m_loaded_images.end() - 1,
                           m_loaded_images.end());
        PIN_ReleaseLock(&m_loaded_images_lock);
    }

    void OnThreadStart(THREADID tid)
    {
        auto* td = new ThreadData();
        SetThreadLocalData(tid, td);
        PIN_GetLock(&m_thread_lock, 0);
        m_seen_threads.insert(tid);
        PIN_ReleaseLock(&m_thread_lock);
    }

    void OnThreadFini(THREADID tid)
    {
        auto* td = GetThreadLocalData(tid);
        if (td)
        {
            td->CloseAllLogs();
            SetThreadLocalData(tid, nullptr);
            PIN_GetLock(&m_thread_lock, 0);
            m_terminated_threads.push_back(td); // freed in Fini()
            PIN_ReleaseLock(&m_thread_lock);
        }
    }

    void Fini()
    {
        for (auto* td : m_terminated_threads) delete td;
        m_terminated_threads.clear();
    }

    // Traced module controls
    void SetTracedModule(std::string v) { traced_module_ = std::move(v); }
    const std::string& TracedModule() const noexcept { return traced_module_; }

    void SetTracingStarted(bool v) noexcept { m_tracing_started = v; }
    bool TracingStarted() const noexcept { return m_tracing_started; }

    TLS_KEY TlsKey() const noexcept { return m_tls_key; }

    std::unique_ptr<ImageManager> m_images; // your manager
    std::string log_dir = "logs"; // optional dir for per-image-per-thread logs

    // Global-ish state used by callbacks:
    std::vector<std::pair<std::string, ADDRINT>> image_base_mappings;
    bool m_tracing_enabled = true; // disabled until module loads if tracing a specific DLL
    std::string traced_module_;
    bool m_tracing_started;

    // Expose lock for rare reads (if you want to lock during read)
    mutable PIN_LOCK m_loaded_images_lock;
    std::vector<LoadedImage> m_loaded_images; // kept sorted by low_

    mutable PIN_LOCK m_thread_lock;
    std::set<THREADID> m_seen_threads;
    std::vector<ThreadData*> m_terminated_threads;

private:
    ADDRINT image_base_;
    TLS_KEY m_tls_key;

public:
    std::string GetImageNameForAddress(ADDRINT addr)
    {
        // Optional lock for safety (image loads are rare)
        PIN_GetLock(&this->m_loaded_images_lock, 0);
        LoadedImage probe("probe", addr, 0, 0);
        auto it = std::upper_bound(this->m_loaded_images.begin(),
                                   this->m_loaded_images.end(), probe);
        if (it == this->m_loaded_images.begin())
        {
            PIN_ReleaseLock(&this->m_loaded_images_lock);
            return "unknown";
        }
        --it;
        if (addr >= it->low_ && addr < it->high_)
        {
            std::string name = it->name_;
            PIN_ReleaseLock(&this->m_loaded_images_lock);
            return PathUtils::GetBaseName(name);
        }
        PIN_ReleaseLock(&this->m_loaded_images_lock);
        return "unknown";
    }


    ADDRINT RebaseAddress(ADDRINT addr)
    {
        PIN_GetLock(&this->m_loaded_images_lock, 0);
        LoadedImage probe("probe", addr, 0, 0);
        auto it = std::upper_bound(this->m_loaded_images.begin(),
                                   this->m_loaded_images.end(), probe);
        if (it == this->m_loaded_images.begin())
        {
            PIN_ReleaseLock(&this->m_loaded_images_lock);
            return addr;
        }
        --it;
        if (addr >= it->low_ && addr < it->high_)
        {
            ADDRINT desired = it->desired_base_;
            PIN_ReleaseLock(&this->m_loaded_images_lock);
            return desired ? (addr - it->low_) + desired : addr;
        }
        PIN_ReleaseLock(&this->m_loaded_images_lock);
        return addr;
    }
};

// -----------------------------------------------------
// Global tool context (lives for process lifetime)
std::unique_ptr<ToolContext> g_context;

// -----------------------------------------------------
// Helpers


static bool ParseImageBaseMapping(const std::string& s, std::string& name, ADDRINT& base)
{
    size_t pos = s.find(':');
    if (pos == std::string::npos) return false;
    name = s.substr(0, pos);
    std::string base_str = s.substr(pos + 1);
    base = 0;
    if (base_str.size() > 2 && base_str[0] == '0' && (base_str[1] == 'x' || base_str[1] == 'X'))
        base = strtoull(base_str.c_str(), nullptr, 16);
    else
        base = strtoull(base_str.c_str(), nullptr, 10);
    return true;
}


// -----------------------------------------------------
// Thread lifecycle

static VOID OnThreadStart(THREADID tid, CONTEXT*, INT32, VOID* v)
{
    static_cast<ToolContext*>(v)->OnThreadStart(tid);
}

static VOID OnThreadFini(THREADID tid, const CONTEXT*, INT32, VOID* v)
{
    static_cast<ToolContext*>(v)->OnThreadFini(tid);
}

// -----------------------------------------------------
// Image load/unload

static VOID OnImageLoad(IMG img, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    std::string img_name = PathUtils::GetBaseName(IMG_Name(img));
    ADDRINT low = IMG_LowAddress(img);
    ADDRINT high = IMG_HighAddress(img);
    ADDRINT desired_base = 0;

    for (const auto& kv : context.image_base_mappings)
    {
        if (kv.first == img_name)
        {
            desired_base = kv.second;
            break;
        }
    }

    if (meta_logger)
    {
        if (desired_base)
        {
            meta_logger->infof("Loaded image: %s range=[0x%llx:0x%llx] rebase->[0x%llx:0x%llx]",
                               img_name.c_str(),
                               asU64(low), asU64(high),
                               asU64(desired_base), asU64((high - low) + desired_base));
        }
        else
        {
            meta_logger->infof("Loaded image: %s range=[0x%llx:0x%llx] (no rebasing)",
                               img_name.c_str(), asU64(low), asU64(high));
        }
    }
    

    context.RegisterLoadedImage(low, high, img_name, desired_base);

    // traced-module-only mode
    if (!context.traced_module_.empty())
    {
        if (img_name == context.traced_module_)
        {
            context.m_images->addImage(img_name, low, high, desired_base);
            context.m_tracing_enabled = true;
            context.m_tracing_started = true;
            if (meta_logger) meta_logger->infof("Tracing started for module: %s", img_name.c_str());
        }
        return;
    }

    // whitelist mode
    if (context.m_images->isWhiteListed(img_name))
    {
        context.m_images->addImage(img_name, low, high, desired_base);
        if (!context.m_tracing_enabled) context.m_tracing_enabled = true;
    }
}

static VOID OnImageUnload(IMG img, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    context.m_images->removeImage(IMG_LowAddress(img));
    // Optional: also erase from m_loaded_images if you want exact accuracy.
}

// -----------------------------------------------------
// Tracing

static VOID record_diff(const CONTEXT* cpu, ADDRINT pc, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    if (!context.m_tracing_enabled || !context.m_images->isInterestingAddress(pc))
    {
        // Avoid carrying stale memory sizes across uninterested instructions
        THREADID _tid = PIN_ThreadId();
        ThreadData* _td = context.GetThreadLocalData(_tid);
        if (_td)
        {
            _td->mem_r_size = 0;
            _td->mem_r2_size = 0;
            _td->mem_w_size = 0;
        }
        return;
    }

    THREADID tid = PIN_ThreadId();
    ThreadData* data = context.GetThreadLocalData(tid);
    if (!data) return;

    // Per-image logger (file per thread per image)
    std::string image_name = context.GetImageNameForAddress(pc);
    std::string sanitized_image_name;
    sanitized_image_name.reserve(image_name.size());
    for (size_t i = 0; i < image_name.size(); ++i)
    {
        char c = image_name[i];
        sanitized_image_name += ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')
                                    ? c
                                    : '_';
    }

    tenet_tracer::Logger* out_logger = nullptr;
    auto it = data->m_image_logs.find(sanitized_image_name);
    if (it == data->m_image_logs.end())
    {
        std::string prefix = KnobOutputFilePrefix.Value();
        PathUtils::EnsureDirectoryExists(prefix);
        // prefix.<image>.log ; handler will NOT append tid (we include tid in name below if desired)
        std::string baseFilename = prefix + "." + sanitized_image_name + ".log";
        // Create builder and conditionally add handlers
        tenet_tracer::LoggerBuilder builder;
        
#if defined(USE_SQLITE3)
        // SQLite mode: use SQLite handler for structured query support (writes to global queue)
        builder.addHandler<tenet_tracer::SqliteLogHandler>(
            g_trace_db,
            sanitized_image_name,
            100  // batch size
        );
        const char* _log_type = "sqlite";
#else
        // File mode: use file handler
        builder.addFileHandler(
            baseFilename,
            0 /* do not roll over */,
            true /*appendThreadId*/,
            false /* no level prefix */);
        const char* _log_type = "file";
#endif
        auto loggerPtr = builder.build();
        loggerPtr->setThreadId(static_cast<unsigned>(tid));
        if (meta_logger)
        {
            meta_logger->infof("Opened log (%s) for image '%s' (tid %u)",
                                _log_type, image_name.c_str(), static_cast<unsigned>(tid));
        }
        out_logger = loggerPtr.get();
        data->m_image_logs[sanitized_image_name] = std::move(loggerPtr);
    }
    else
    {
        out_logger = it->second.get();
    }
    if (!out_logger) return;

    // Build entry
    std::ostringstream oss;
    oss << std::hex;

    // Register deltas
    ADDRINT val = 0;
    const int cpu_size = static_cast<int>(data->m_cpu.size());
    for (int r = static_cast<int>(REG_GR_BASE); r <= static_cast<int>(REG_GR_LAST); ++r)
    {
        const int reg_idx = r - static_cast<int>(REG_GR_BASE);
        if (reg_idx < 0 || reg_idx >= cpu_size) continue;

        PIN_GetContextRegval(cpu, static_cast<REG>(r), reinterpret_cast<UINT8*>(&val));
        if (val == data->m_cpu[reg_idx]) continue;

        oss << REG_StringShort(static_cast<REG>(r)) << "=0x" << val << ",";
        data->m_cpu[reg_idx] = val;
    }

    // PC (rebased if needed)
    ADDRINT adjusted_pc = context.RebaseAddress(pc);
    oss << PC << "=0x" << adjusted_pc;

    // Memory reads/writes (dump bytes)
    if (data->mem_r_size)
    {
        const UINT32 to_copy = static_cast<UINT32>(std::min<ADDRINT>(sizeof(data->m_scratch), data->mem_r_size));
        std::memset(data->m_scratch, 0, to_copy);
        PIN_SafeCopy(data->m_scratch, reinterpret_cast<const void*>(data->mem_r_addr), to_copy);
        ADDRINT a = context.RebaseAddress(data->mem_r_addr);
        oss << ",mr=0x" << a << ":";
        for (UINT32 i = 0; i < to_copy; ++i)
            oss << std::setw(2) << std::setfill('0') << (static_cast<unsigned>(static_cast<unsigned char>(data->
                m_scratch[i])) & 0xff);
        data->mem_r_size = 0;
    }
    if (data->mem_r2_size)
    {
        const UINT32 to_copy = static_cast<UINT32>(std::min<ADDRINT>(sizeof(data->m_scratch), data->mem_r2_size));
        std::memset(data->m_scratch, 0, to_copy);
        PIN_SafeCopy(data->m_scratch, reinterpret_cast<const void*>(data->mem_r2_addr), to_copy);
        ADDRINT a = context.RebaseAddress(data->mem_r2_addr);
        oss << ",mr=0x" << a << ":";
        for (UINT32 i = 0; i < to_copy; ++i)
            oss << std::setw(2) << std::setfill('0') << (static_cast<unsigned>(static_cast<unsigned char>(data->
                m_scratch[i])) & 0xff);
        data->mem_r2_size = 0;
    }
    if (data->mem_w_size)
    {
        const UINT32 to_copy = static_cast<UINT32>(std::min<ADDRINT>(sizeof(data->m_scratch), data->mem_w_size));
        std::memset(data->m_scratch, 0, to_copy);
        PIN_SafeCopy(data->m_scratch, reinterpret_cast<const void*>(data->mem_w_addr), to_copy);
        ADDRINT a = context.RebaseAddress(data->mem_w_addr);
        oss << ",mw=0x" << a << ":";
        for (UINT32 i = 0; i < to_copy; ++i)
            oss << std::setw(2) << std::setfill('0') << (static_cast<unsigned>(static_cast<unsigned char>(data->
                m_scratch[i])) & 0xff);
        data->mem_w_size = 0;
    }

    out_logger->log(oss.str());
}

static VOID record_read(THREADID tid, ADDRINT access_addr, UINT32 access_size, VOID* v)
{
    ThreadData* data = static_cast<ToolContext*>(v)->GetThreadLocalData(tid);
    if (!data) return;
    data->mem_r_addr = access_addr;
    data->mem_r_size = access_size;
}

static VOID record_read2(THREADID tid, ADDRINT access_addr, UINT32 access_size, VOID* v)
{
    ThreadData* data = static_cast<ToolContext*>(v)->GetThreadLocalData(tid);
    if (!data) return;
    data->mem_r2_addr = access_addr;
    data->mem_r2_size = access_size;
}

static VOID record_write(THREADID tid, ADDRINT access_addr, UINT32 access_size, VOID* v)
{
    ThreadData* data = static_cast<ToolContext*>(v)->GetThreadLocalData(tid);
    if (!data) return;
    data->mem_w_addr = access_addr;
    data->mem_w_size = access_size;
}

static VOID OnInst(INS ins, VOID* v)
{
    // If instruction uses memory, capture addresses/sizes
    if (INS_IsMemoryRead(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_read),
                       IARG_THREAD_ID,
                       IARG_MEMORYREAD_EA,
                       IARG_MEMORYREAD_SIZE,
                       IARG_PTR, v,
                       IARG_END);
    }
    if (INS_HasMemoryRead2(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_read2),
                       IARG_THREAD_ID,
                       IARG_MEMORYREAD2_EA,
                       IARG_MEMORYREAD_SIZE, // IARG_MEMORYREAD2_SIZE does not exist, but we can assume that both operands have the same size
                       IARG_PTR, v,
                       IARG_END);
    }
    if (INS_IsMemoryWrite(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_write),
                       IARG_THREAD_ID,
                       IARG_MEMORYWRITE_EA,
                       IARG_MEMORYWRITE_SIZE,
                       IARG_PTR, v,
                       IARG_END);
    }

    // Dump diff after memory addresses have been captured
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_diff),
                   IARG_CONST_CONTEXT,
                   IARG_INST_PTR,
                   IARG_PTR, v,
                   IARG_END);
}

// -----------------------------------------------------
// Shutdown & exceptions

/*!
 * PrepareForFini callback - stop background threads before final cleanup
 */
static VOID PrepareForFini(VOID* v)
{
#if defined(USE_SQLITE3)
    // Stop background flush thread (it will flush remaining entries)
    if (meta_logger) meta_logger->info("Stopping background SQLite flush thread...");
    tenet_tracer::SqliteLogHandler::StopBackgroundFlushThread();
    if (meta_logger) meta_logger->info("Background flush thread stopped");
#endif
}

static VOID Fini(INT32, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);

    // Move any surviving TDs to terminated list
    for (THREADID tid : context.m_seen_threads)
    {
        if (auto* data = context.GetThreadLocalData(tid))
        {
            context.m_terminated_threads.push_back(data);
            context.SetThreadLocalData(tid, nullptr);
        }
    }

    // Close & free
    for (auto* data : context.m_terminated_threads)
    {
        if (data)
        {
            data->CloseAllLogs();
            delete data;
        }
    }
    context.m_terminated_threads.clear();

#if defined(USE_SQLITE3)
    // Flush any remaining entries in queue (background thread should have done most)
    if (g_trace_db) {
        if (meta_logger) meta_logger->info("Flushing remaining trace queue to SQLite database...");
        tenet_tracer::SqliteLogHandler::FlushQueueToDatabase(g_trace_db);
        if (meta_logger) meta_logger->info("Trace queue flushed successfully");
        
        // Force WAL checkpoint before closing
        sqlite3_exec(g_trace_db, "PRAGMA wal_checkpoint(FULL);", nullptr, nullptr, nullptr);
        sqlite3_close(g_trace_db);
        g_trace_db = nullptr;
        if (meta_logger) meta_logger->info("SQLite database closed");
    }
#endif
}

static EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID /*tid*/, EXCEPTION_INFO* pExceptInfo,
                                               PHYSICAL_CONTEXT*, VOID*)
{
    EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
    EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
    std::cerr << "Exception class " << cl << " : " << PIN_ExceptionToString(pExceptInfo) << std::endl;
    if (meta_logger)
        meta_logger->errorf("Exception occurred class %u : %s",
                            static_cast<unsigned>(cl),
                            PIN_ExceptionToString(pExceptInfo).c_str());
    return EHR_UNHANDLED;
}

// -----------------------------------------------------
// Usage

static INT32 Usage()
{
    std::cerr << "This tool logs register deltas and memory accesses per thread/module.\n\n";
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

// -----------------------------------------------------
// Entry point

int main(int argc, char* argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();

    PIN_AddInternalExceptionHandler(ExceptionHandler, nullptr);

    // Global logs (rotated at 10MB)
    const auto metaFile = KnobOutputFilePrefix.Value() + ".meta.txt";

    meta_logger = tenet_tracer::LoggerBuilder()
                  .addFileHandler(metaFile, 10 * 1024 * 1024, false)
                  .build();

#if defined(USE_SQLITE3)
    // Initialize global trace queue lock
    PIN_InitLock(&tenet_tracer::g_trace_queue_lock);
    
    // Initialize SQLite database for structured trace logging
    const auto outputFile = KnobOutputFilePrefix.Value() + ".db";
    int rc = sqlite3_open(outputFile.c_str(), &g_trace_db);
    if (rc == SQLITE_OK)
    {
        meta_logger->infof("SQLite trace database opened: %s", outputFile.c_str());
        // Verify database is accessible by creating a test table
        char* errMsg = nullptr;
        rc = sqlite3_exec(g_trace_db, "CREATE TABLE IF NOT EXISTS _init_test (id INTEGER);", nullptr, nullptr, &errMsg);
        if (rc == SQLITE_OK) {
            meta_logger->info("SQLite database initialized and writable");
            sqlite3_exec(g_trace_db, "DROP TABLE IF EXISTS _init_test;", nullptr, nullptr, nullptr);
        } else {
            meta_logger->errorf("SQLite database not writable: %s", errMsg ? errMsg : "unknown error");
            if (errMsg) sqlite3_free(errMsg);
        }
        
        // Start background flush thread to periodically write batches
        tenet_tracer::SqliteLogHandler::StartBackgroundFlushThread(g_trace_db);
        meta_logger->info("Background SQLite flush thread started");
    }
    else
    {
        const char* errMsg = g_trace_db ? sqlite3_errmsg(g_trace_db) : "unknown error";
        meta_logger->errorf("Failed to open SQLite database %s: %s (rc=%d)", outputFile.c_str(), errMsg, rc);
        if (g_trace_db) {
            sqlite3_close(g_trace_db);
        }
        g_trace_db = nullptr;
    }
#else
    const auto outputFile = KnobOutputFilePrefix.Value() + ".log";
    meta_logger->infof("Trace logs are written to: %s", outputFile.c_str());
#endif
    meta_logger->infof("Metadata logging to: %s", metaFile.c_str());

    // Global tool context
    g_context = std::make_unique<ToolContext>();
    meta_logger->info("Tool context initialized");

    // Traced module mode
    if (!KnobTraceModule.Value().empty())
    {
        g_context->traced_module_ = KnobTraceModule.Value();
        g_context->m_tracing_enabled = false; // start disabled until module loads
        if (meta_logger)
            meta_logger->infof("Specified traced module: %s", g_context->traced_module_.c_str());
    }

    meta_logger->info("Configuration complete");

    // Whitelist modules
    for (unsigned i = 0; i < KnobModuleWhitelist.NumberOfValues(); ++i)
    {
        const std::string name = KnobModuleWhitelist.Value(i);
        if (meta_logger) meta_logger->infof("White-listing image: %s", name.c_str());
        g_context->m_images->addWhiteListedImage(name);
        g_context->m_tracing_enabled = false; // enable only when first whitelisted image loads
    }

    // Image base remaps
    for (unsigned i = 0; i < KnobImageBase.NumberOfValues(); ++i)
    {
        std::string val = KnobImageBase.Value(i), name;
        ADDRINT base = 0;
        if (ParseImageBaseMapping(val, name, base))
        {
            g_context->image_base_mappings.emplace_back(name, base);
            if (meta_logger)
                meta_logger->infof("Image base mapping: %s:0x%llx",
                                   name.c_str(), asU64(base));
        }
    }

    // Register callbacks (pass raw ptr for v)
    PIN_AddThreadStartFunction(OnThreadStart, g_context.get());
    PIN_AddThreadFiniFunction(OnThreadFini, g_context.get());

    IMG_AddInstrumentFunction(OnImageLoad, g_context.get());
    IMG_AddUnloadFunction(OnImageUnload, g_context.get());

    INS_AddInstrumentFunction(OnInst, g_context.get());

    PIN_AddPrepareForFiniFunction(PrepareForFini, nullptr);
    PIN_AddFiniFunction(Fini, g_context.get());

    // Run the target (never returns)
    PIN_StartProgram();
    return 0;
}

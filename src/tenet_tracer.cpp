//
// pintenet.cpp, a Proof-of-Concept Tenet Tracer with targeted module support
//
//  -- by Patrick Biernat & Markus Gaasedelen
//                   @ RET2 Systems, Inc.
//
// Adaptions from the CodeCoverage pin tool by Agustin Gianni as
// contributed to Lighthouse: https://github.com/gaasedelen/lighthouse
//
// Additional modifications were made to support tracing a specific DLL
// within an executable, inspired by the functionality of the TenetTracer
// project. In particular, a new knob (`-m`) allows the user to specify
// the name of a module to trace. When set, tracing will not begin until
// the specified module is loaded, and only instructions originating from
// that module will be logged. This mirrors TenetTracer's concept of
// selecting a `TRACED_MODULE` for DLL-in-EXE scenarios.
//

#include "pin.H"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <utility>
#include <map>

#if defined(_WIN32) || defined(_WIN64)
namespace WINDOWS
{
#include <windows.h>
}
#endif

#include "ImageManager.h"

using std::ofstream;

ofstream* g_log;
ofstream* meta_log;

#ifdef __i386__
#define PC "eip"
#else
#define PC "rip"
#endif

//
// Tool Arguments
//

static KNOB<std::string> KnobModuleWhitelist(KNOB_MODE_APPEND, "pintool", "w", "",
    "Add a module to the whitelist. If none is specified, every module is white-listed. Example: calc.exe");

KNOB<std::string> KnobOutputFilePrefix(KNOB_MODE_WRITEONCE, "pintool", "o", "trace",
    "Prefix of the output file. If none is specified, 'trace' is used.");

static KNOB<std::string> KnobImageBase(KNOB_MODE_APPEND, "pintool", "i", "",
    "Image base address remapping. Syntax: ImageName:0xBase. Example: -i WowT.exe:0x140000000");

//
// New knob: traced module name
//
// When specified, tracing will begin only after this module (DLL) is
// loaded into the target process. Only instructions that originate from
// the selected module will be recorded. This mirrors the TenetTracer
// `TRACED_MODULE` concept, allowing users to focus on DLLs loaded by
// an executable rather than the executable itself.
static KNOB<std::string> KnobTraceModule(KNOB_MODE_WRITEONCE, "pintool", "m", "",
    "Name of the module (DLL) to trace. When set, tracing does not start until this module is loaded.");

//
// Misc / Util
//

#if defined(TARGET_WINDOWS)
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

static std::string base_name(const std::string& path)
{
    std::string::size_type idx = path.rfind(PATH_SEPARATOR);
    std::string name = (idx == std::string::npos) ? path : path.substr(idx + 1);
    return name;
}

//
// Per thread data structure. This is mainly done to avoid locking.
// - Per-thread map of executed basic blocks, and their size.
//

struct ThreadData
{
    ADDRINT m_cpu_pc;
    ADDRINT m_cpu[REG_GR_LAST + 1];

    ADDRINT mem_w_addr;
    ADDRINT mem_w_size;
    ADDRINT mem_r_addr;
    ADDRINT mem_r_size;
    ADDRINT mem_r2_addr;
    ADDRINT mem_r2_size;

    // Map from image name to log stream
    std::map<std::string, ofstream*> m_image_logs;

    char m_scratch[512 * 2]; // fxsave has the biggest memory operand
};

//
// Tool Infrastructure
//

class ToolContext
{
public:
    // Image base as provided by the user (via knob)
    ADDRINT image_base_;

    // When tracing a specific module (DLL) within the target process, this
    // field holds the module's base name. If empty, all modules may be traced
    // depending on the whitelist. See KnobTraceModule and the documentation
    // on tracing DLLs within an EXE.
    std::string traced_module;

    // Flag indicating that tracing for the traced_module has started. It
    // remains false until the specified module is loaded. This ensures
    // instructions executed before the module is present are not logged.
    bool m_tracing_started;

    // The image manager allows us to keep track of loaded images.
    ImageManager* m_images;

    ToolContext() : m_tracing_started(false), m_images(nullptr)
    {
        // Initialize the image base to the knob value if set
        if (!KnobImageBase.Value().empty())
        {
            image_base_ = std::stoull(KnobImageBase.Value(), nullptr, 16);
        }
        else
        {
            // Default fallback (0 for no base adjustment)
            image_base_ = 0;
        }

        PIN_InitLock(&m_loaded_images_lock);
        PIN_InitLock(&m_thread_lock);
        m_tls_key = PIN_CreateThreadDataKey(nullptr);
    }

    // Method to return the image base
    ADDRINT getImageBase() const
    {
        return image_base_;
    }

    ThreadData* GetThreadLocalData(THREADID tid) const
    {
        return static_cast<ThreadData*>(PIN_GetThreadData(m_tls_key, tid));
    }

    void setThreadLocalData(THREADID tid, ThreadData* data) const
    {
        PIN_SetThreadData(m_tls_key, data, tid);
    }

    // Method to find the image base of a given address
    ADDRINT findImageBaseForAddress(ADDRINT addr) const
    {
        for (const auto& img : m_loaded_images)
        {
            if (addr >= img.low_ && addr <= img.high_)
            {
                return img.low_;
            }
        }
        return 0; // Return 0 if no image base is found for the given address
    }

    // Trace file used for 'monolithic' execution traces.
    //TraceFile* m_trace;

    // Keep track of _all_ the loaded images.
    std::vector<LoadedImage> m_loaded_images;
    PIN_LOCK m_loaded_images_lock;

    // Thread tracking utilities.
    std::set<THREADID> m_seen_threads;
    std::vector<ThreadData*> m_terminated_threads;
    PIN_LOCK m_thread_lock;

    // Flag that indicates that tracing is enabled. Always true if there are no whitelisted images.
    bool m_tracing_enabled = true;

    // TLS key used to store per-thread data.
    TLS_KEY m_tls_key;

    // Map of image name to desired base (for rebasing)
    std::vector<std::pair<std::string, ADDRINT>> image_base_mappings;
};

// Utility to ensure directory exists for a given file path prefix
static void ensure_directory_for_prefix(const std::string& prefix)
{
    size_t pos = prefix.find_last_of("/\\");
    if (pos == std::string::npos) return;
    std::string dir = prefix.substr(0, pos);
    if (dir.empty()) return;
#if defined(_WIN32) || defined(_WIN64)
    // Recursively create directories
    size_t start = 0;
    while (true)
    {
        size_t sep = dir.find_first_of("/\\", start);
        std::string subdir = dir.substr(0, sep);
        if (!subdir.empty())
        {
            WINDOWS::CreateDirectoryA(subdir.c_str(), nullptr);
        }
        if (sep == std::string::npos) break;
        start = sep + 1;
    }
#endif
}

// Utility to get image name for an address
static std::string get_image_name_for_address(const ToolContext& context, ADDRINT addr)
{
    for (size_t i = 0; i < context.m_loaded_images.size(); ++i)
    {
        const LoadedImage& img = context.m_loaded_images[i];
        if (addr >= img.low_ && addr < img.high_)
        {
            return base_name(img.name_);
        }
    }
    return "unknown";
}

// Thread creation event handler.
static VOID OnThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    auto data = new ThreadData;
    // Don't use memset as it destroys the std::map constructor!
    // Instead, manually initialize the primitive members
    data->m_cpu_pc = 0;
    for (int i = 0; i <= REG_GR_LAST; ++i) {
        data->m_cpu[i] = 0;
    }
    data->mem_w_addr = 0;
    data->mem_w_size = 0;
    data->mem_r_addr = 0;
    data->mem_r_size = 0;
    data->mem_r2_addr = 0;
    data->mem_r2_size = 0;
    memset(data->m_scratch, 0, sizeof(data->m_scratch));
    // m_image_logs is a std::map and will be initialized by its constructor

    context.setThreadLocalData(tid, data);
    PIN_GetLock(&context.m_thread_lock, 1);
    {
        context.m_seen_threads.insert(tid);
    }
    PIN_ReleaseLock(&context.m_thread_lock);
}

// Thread destruction event handler.
static VOID OnThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 c, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);
    for (auto it = data->m_image_logs.begin(); it != data->m_image_logs.end(); ++it)
    {
        if (it->second)
        {
            it->second->close();
            delete it->second;
        }
    }
    data->m_image_logs.clear();
    PIN_GetLock(&context.m_thread_lock, 1);
    {
        context.m_seen_threads.erase(tid);
        context.m_terminated_threads.push_back(data);
    }
    PIN_ReleaseLock(&context.m_thread_lock);
}

// Utility to parse ImageName:0xBase from knob value
static bool parse_image_base_mapping(const std::string& s, std::string& name, ADDRINT& base)
{
    size_t pos = s.find(":");
    if (pos == std::string::npos) return false;
    name = s.substr(0, pos);
    std::string base_str = s.substr(pos + 1);
    base = 0;
    if (base_str.size() > 2 && (base_str[0] == '0' && (base_str[1] == 'x' || base_str[1] == 'X')))
        base = strtoull(base_str.c_str(), nullptr, 16);
    else
        base = strtoull(base_str.c_str(), nullptr, 10);
    return true;
}

// Image load event handler.
static VOID OnImageLoad(IMG img, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    std::string img_name = base_name(IMG_Name(img));
    ADDRINT low = IMG_LowAddress(img);
    ADDRINT high = IMG_HighAddress(img);
    ADDRINT desired_base = 0;
    // Look for mapping
    for (size_t i = 0; i < context.image_base_mappings.size(); ++i)
    {
        if (context.image_base_mappings[i].first == img_name)
        {
            desired_base = context.image_base_mappings[i].second;
            break;
        }
    }

    // Write to meta log with detailed rebasing info
    if (meta_log)
    {
        if (desired_base != 0)
        {
            ADDRINT rebased_high = (high - low) + desired_base;
            *meta_log << "Loaded image: " << img_name << " with range 0x" << std::hex << low << ":0x" << high
                << " and rebasing it to 0x" << desired_base << ":0x" << rebased_high << std::endl;
        }
        else
        {
            *meta_log << "Loaded image: " << img_name << " with range 0x" << std::hex << low << ":0x" << high
                << " (no rebasing)" << std::endl;
        }
    }

    // Write to main log with rebased range (or original if no rebasing)
    if (desired_base != 0)
    {
        ADDRINT rebased_high = (high - low) + desired_base;
        *g_log << "Loaded image: 0x" << std::hex << desired_base << ":0x" << rebased_high << " -> " << img_name << std::endl;
    }
    else
    {
        *g_log << "Loaded image: 0x" << std::hex << low << ":0x" << high << " -> " << img_name << std::endl;
    }

    PIN_GetLock(&context.m_loaded_images_lock, 1);
    {
        context.m_loaded_images.push_back(LoadedImage(IMG_Name(img), low, high, desired_base));
    }
    PIN_ReleaseLock(&context.m_loaded_images_lock);

    // If a traced module name was specified, enable tracing only when it is loaded
    if (!context.traced_module.empty())
    {
        // compare case sensitive; the user should pass the exact base name
        if (img_name == context.traced_module)
        {
            context.m_images->addImage(img_name, low, high, desired_base);
            context.m_tracing_enabled = true;
            context.m_tracing_started = true;
            if (meta_log)
            {
                *meta_log << "Tracing started for module: " << img_name << std::endl;
            }
        }
        // Do not add any other images to the ImageManager if a traced module is specified.
        return;
    }

    // Fall back to whitelist logic when no specific module is targeted
    if (context.m_images->isWhiteListed(img_name))
    {
        context.m_images->addImage(img_name, low, high, desired_base);
        if (!context.m_tracing_enabled)
            context.m_tracing_enabled = true;
    }
}

// Image unload event handler.
static VOID OnImageUnload(IMG img, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    context.m_images->removeImage(IMG_LowAddress(img));
}

//
// Tracing
//

static ADDRINT rebase_address(const ToolContext& context, ADDRINT addr)
{
    // Find which loaded image this address belongs to
    for (size_t i = 0; i < context.m_loaded_images.size(); ++i)
    {
        const LoadedImage& img = context.m_loaded_images[i];
        if (addr >= img.low_ && addr < img.high_)
        {
            // See if a desired base is set
            if (img.desired_base_ != 0)
            {
                return (addr - img.low_) + img.desired_base_;
            }
            break;
        }
    }
    // No rebase
    return addr;
}

// Utility to sanitize image name for file name
static std::string sanitize_image_name(const std::string& name)
{
    std::string out;
    for (size_t i = 0; i < name.size(); ++i)
    {
        char c = name[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')
        {
            out += c;
        }
        else
        {
            out += '_';
        }
    }
    return out;
}

static VOID record_diff(const CONTEXT* cpu, ADDRINT pc, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    // Only proceed if tracing is enabled and the address is interesting
    if (!context.m_tracing_enabled || !context.m_images->isInterestingAddress(pc))
        return;
    auto tid = PIN_ThreadId();
    ThreadData* data = context.GetThreadLocalData(tid);
    if (!data)
        return;

    // Determine image name for current PC
    std::string image_name = get_image_name_for_address(context, pc);
    std::string sanitized_image_name = sanitize_image_name(image_name);

    // Open log file for this image/thread if not already open
    ofstream* out_file = nullptr;
    if (data->m_image_logs.count(sanitized_image_name) == 0)
    {
        // Compose file name: prefix.sanitizedimagename_tid.log
        std::string prefix = KnobOutputFilePrefix.Value();
        ensure_directory_for_prefix(prefix);
        char filename[512] = {};
        sprintf(filename, "%s.%s_%u.log", prefix.c_str(), sanitized_image_name.c_str(), tid);
        out_file = new ofstream;
        out_file->open(filename);
        if (!out_file || !out_file->is_open())
        {
            if (g_log)
            {
                *g_log << "[ERROR] Failed to open log file: " << filename << " for image '" << image_name << "' (tid "
                    << tid << ")" << std::endl;
            }
            delete out_file;
            return;
        }
        if (meta_log)
        {
            *meta_log << "[INFO] Opened log file: " << filename << " for image '" << image_name << "' (tid " << tid << ")"
                << std::endl;
        }
        *out_file << std::hex;
        data->m_image_logs[sanitized_image_name] = out_file;
    }
    else
    {
        out_file = data->m_image_logs[sanitized_image_name];
    }

    // Defensive check before writing
    if (!out_file || !out_file->is_open())
        return;

    // Dump register delta
    ADDRINT val = 0;
    int cpu_size = sizeof(data->m_cpu) / sizeof(data->m_cpu[0]);
    for (int reg = REG_GR_BASE; reg <= static_cast<int>(REG_GR_LAST); ++reg)
    {
        int reg_idx = reg - static_cast<int>(REG_GR_BASE);
        if (reg_idx < 0 || reg_idx >= cpu_size)
            continue;
        PIN_GetContextRegval(cpu, static_cast<REG>(reg), reinterpret_cast<UINT8*>(&val));
        if (val == data->m_cpu[reg])
            continue;
        *out_file << REG_StringShort(static_cast<REG>(reg)) << "=0x" << val << ",";
        data->m_cpu[reg] = val;
    }

    // Use rebasing for PC
    ADDRINT adjusted_pc = rebase_address(context, pc);
    *out_file << PC << "=0x" << adjusted_pc;

    // Memory read/write logs
    if (data->mem_r_size)
    {
        memset(data->m_scratch, 0, data->mem_r_size);
        PIN_SafeCopy(data->m_scratch, reinterpret_cast<const void*>(data->mem_r_addr), data->mem_r_size);
        ADDRINT adjusted_mem_r_addr = rebase_address(context, data->mem_r_addr);
        *out_file << ",mr=0x" << adjusted_mem_r_addr << ":";
        for (UINT32 i = 0; i < data->mem_r_size; i++)
        {
            *out_file << std::hex << std::setw(2) << std::setfill('0') << (static_cast<unsigned char>(data->m_scratch[i])
                & 0xff);
        }
        data->mem_r_size = 0;
    }
    if (data->mem_r2_size)
    {
        memset(data->m_scratch, 0, data->mem_r2_size);
        PIN_SafeCopy(data->m_scratch, reinterpret_cast<const void*>(data->mem_r2_addr), data->mem_r2_size);
        ADDRINT adjusted_mem_r2_addr = rebase_address(context, data->mem_r2_addr);
        *out_file << ",mr=0x" << adjusted_mem_r2_addr << ":";
        for (UINT32 i = 0; i < data->mem_r2_size; i++)
        {
            *out_file << std::hex << std::setw(2) << std::setfill('0') << (static_cast<unsigned char>(data->m_scratch[i])
                & 0xff);
        }
        data->mem_r2_size = 0;
    }
    if (data->mem_w_size)
    {
        memset(data->m_scratch, 0, data->mem_w_size);
        PIN_SafeCopy(data->m_scratch, reinterpret_cast<const void*>(data->mem_w_addr), data->mem_w_size);
        ADDRINT adjusted_mem_w_addr = rebase_address(context, data->mem_w_addr);
        *out_file << ",mw=0x" << adjusted_mem_w_addr << ":";
        for (UINT32 i = 0; i < data->mem_w_size; i++)
        {
            *out_file << std::hex << std::setw(2) << std::setfill('0') << (static_cast<unsigned char>(data->m_scratch[i])
                & 0xff);
        }
        data->mem_w_size = 0;
    }
    *out_file << std::endl;
}

VOID record_read(THREADID tid, ADDRINT access_addr, UINT32 access_size, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);
    data->mem_r_addr = access_addr;
    data->mem_r_size = access_size;
}

VOID record_read2(THREADID tid, ADDRINT access_addr, UINT32 access_size, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);
    data->mem_r2_addr = access_addr;
    data->mem_r2_size = access_size;
}

VOID record_write(THREADID tid, ADDRINT access_addr, UINT32 access_size, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    ThreadData* data = context.GetThreadLocalData(tid);
    data->mem_w_addr = access_addr;
    data->mem_w_size = access_size;
}

VOID OnInst(INS ins, VOID* v)
{
    //
    // *always* dump a diff since the last instruction
    //

    INS_InsertCall(
        ins, IPOINT_BEFORE,
        AFUNPTR(record_diff),
        IARG_CONST_CONTEXT,
        IARG_INST_PTR,
        IARG_PTR, v,
        IARG_END);

    //
    // if this instruction will perform a mem r/w, inject a call to record the
    // address of interest. this will be used by the *next* state diff / dump
    //

    if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins))
    {
        if (INS_IsMemoryRead(ins))
        {
            INS_InsertCall(
                ins, IPOINT_BEFORE,
                AFUNPTR(record_read),
                IARG_THREAD_ID,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_PTR, v,
                IARG_END);
        }

        if (INS_HasMemoryRead2(ins))
        {
            //assert(INS_IsMemoryRead(ins) == false);
            INS_InsertCall(
                ins, IPOINT_BEFORE,
                AFUNPTR(record_read2),
                IARG_THREAD_ID,
                IARG_MEMORYREAD2_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_PTR, v,
                IARG_END);
        }

        if (INS_IsMemoryWrite(ins))
        {
            INS_InsertCall(
                ins, IPOINT_BEFORE,
                AFUNPTR(record_write),
                IARG_THREAD_ID,
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_PTR, v,
                IARG_END);
        }
    }
}

static VOID Fini(INT32 code, VOID* v)
{
    auto& context = *static_cast<ToolContext*>(v);
    for (THREADID i : context.m_seen_threads)
    {
        ThreadData* data = context.GetThreadLocalData(i);
        context.m_terminated_threads.push_back(data);
    }
    for (const auto& data : context.m_terminated_threads)
    {
        for (std::map<std::string, ofstream*>::const_iterator it = data->m_image_logs.begin(); it != data->m_image_logs.
            end(); ++it)
        {
            if (it->second)
            {
                it->second->close();
                delete it->second;
            }
        }
    }
    g_log->close();
    if (meta_log) {
        meta_log->close();
        delete meta_log;
    }
}

int main(int argc, char* argv[])
{
    // Initialize symbol processing
    PIN_InitSymbols();

    // Initialize PIN.
    if (PIN_Init(argc, argv))
    {
        std::cerr << "Error initializing PIN, PIN_Init failed!" << std::endl;
        return -1;
    }

    auto logFile = KnobOutputFilePrefix.Value() + ".log";
    g_log = new ofstream;
    g_log->open(logFile.c_str());
    *g_log << std::hex;

    auto metaFile = KnobOutputFilePrefix.Value() + ".meta.txt";
    meta_log = new ofstream;
    meta_log->open(metaFile.c_str());

    // Initialize the tool context
    auto context = new ToolContext();
    context->m_images = new ImageManager();

    // Store the traced module name from the knob into the context. This must be
    // done after the context is created and knobs are parsed. The value is the
    // base name of the DLL that should be traced exclusively.
    if (!KnobTraceModule.Value().empty())
    {
        context->traced_module = KnobTraceModule.Value();
        // When a traced module is specified, disable tracing initially to
        // suppress logging until the module is loaded. This parallels TenetTracer's
        // behaviour of deferring tracing until the DLL appears.
        context->m_tracing_enabled = false;
        if (meta_log)
        {
            *meta_log << "Specified traced module: " << context->traced_module << std::endl;
        }
    }

    for (unsigned i = 0; i < KnobModuleWhitelist.NumberOfValues(); ++i)
    {
        if (meta_log)
            *meta_log << "White-listing image: " << KnobModuleWhitelist.Value(i) << '\n';
        context->m_images->addWhiteListedImage(KnobModuleWhitelist.Value(i));
        context->m_tracing_enabled = false;
    }

    // Parse image base mappings from knob
    for (unsigned i = 0; i < KnobImageBase.NumberOfValues(); ++i)
    {
        std::string val = KnobImageBase.Value(i);
        std::string name;
        ADDRINT base = 0;
        if (parse_image_base_mapping(val, name, base))
        {
            context->image_base_mappings.push_back(std::make_pair(name, base));
            if (meta_log)
                *meta_log << "Image base mapping: " << name << ":0x" << std::hex << base << std::endl;
        }
    }

    // Handlers for thread creation and destruction.
    PIN_AddThreadStartFunction(OnThreadStart, context);
    PIN_AddThreadFiniFunction(OnThreadFini, context);

    // Handlers for image loading and unloading.
    IMG_AddInstrumentFunction(OnImageLoad, context);
    IMG_AddUnloadFunction(OnImageUnload, context);

    // Handlers for instrumentation events.
    INS_AddInstrumentFunction(OnInst, context);

    // Handler for program exits.
    PIN_AddFiniFunction(Fini, context);

    PIN_StartProgram();
    return 0;
}
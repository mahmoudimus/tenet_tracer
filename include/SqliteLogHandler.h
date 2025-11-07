/*
// Example of how to use SqliteLogHandler with tenet_tracer
//
// This shows how to initialize and use the SQLite handler instead of or
// in addition to file-based logging.
// #include <sqlite3.h>
// #include "Logger.h"
// #include "SqliteLogHandler.h"

// void example_sqlite_usage() {
//     // 1. Open or create a SQLite database
//     sqlite3* db = nullptr;
//     int rc = sqlite3_open("trace.db", &db);
//     if (rc != SQLITE_OK) {
//         // Handle error
//         return;
//     }

//     // 2. Create a logger with SQLite handler
//     auto logger = tenet_tracer::LoggerBuilder()
//                       .addHandler<tenet_tracer::SqliteLogHandler>(
//                           db,
//                           "trace",        // table name prefix
//                           100             // batch size (default: 100)
//                       )
//                       .build();

//     // 3. Set thread ID if needed
//     logger->setThreadId(1234);

//     // 4. Log trace entries (formatted as: reg=0xval,reg=0xval,rip=0xval,mr=0xaddr:bytes,...)
//     logger->log("rax=0x1234,rbx=0x5678,rip=0x400000");
//     logger->log("rcx=0xabcd,rdx=0xef01,rip=0x400004,mr=0x7fff0000:4142434445464748");
//     logger->log("rax=0x9999,rip=0x400008,mw=0x7fff0000:0102030405060708");

//     // 5. Close logger (flushes pending writes)
//     logger->close();

//     // 6. Close database
//     sqlite3_close(db);
// }
//
// // Alternative: Using both file and SQLite handlers simultaneously
// void example_dual_logging() {
//     sqlite3* db = nullptr;
//     sqlite3_open("trace.db", &db);

//     auto logger = tenet_tracer::LoggerBuilder()
//                       // File handler for human-readable logs
//                       .addFileHandler("trace.txt", 0, false, false)
//                       // SQLite handler for structured queries
//                       .addHandler<tenet_tracer::SqliteLogHandler>(db, "trace", 100)
//                       .build();

//     logger->setThreadId(1234);

//     // This will write to both file and database
//     logger->log("rax=0x1234,rip=0x400000");

//     logger->close();
//     sqlite3_close(db);
// }

// How to integrate? after creating meta_logger:

   #ifdef USE_SQLITE3
   sqlite3* trace_db = nullptr;
   if (sqlite3_open("tenet_trace.db", &trace_db) == SQLITE_OK) {
       g_logger = tenet_tracer::LoggerBuilder()
                      .addHandler<tenet_tracer::SqliteLogHandler>(
                          trace_db,
                          KnobOutputFilePrefix.Value(),
                          100  // batch size
                      )
                      .build();

       meta_logger->info("SQLite trace database opened: tenet_trace.db");
   }ESCschema
sqlite3 tenet_trace.db ".schema trace_trace"

// Count total trace entries
sqlite3 tenet_trace.db "SELECT COUNT(*) FROM trace_trace;"

// Show most frequently executed PCs
sqlite3 tenet_trace.db "SELECT printf('0x%X', pc), COUNT(*) as cnt FROM trace_trace GROUP BY pc ORDER BY cnt DESC LIMIT 10;"

// Export specific thread back to raw format
python3 dump_trace_db.py tenet_trace.db --tid 1234 --output thread_1234.log

// Show statistics
python3 dump_trace_db.py tenet_trace.db --stats
*/

/*
From the Pin example, the main takeaway is:

**Separate instrumentation from I/O** — use a producer-consumer pattern with dedicated I/O threads.

**Key pattern:**
1. **Fast instrumentation path** — app threads just fill buffers/queues (no I/O)
2. **Dedicated I/O threads** — separate worker threads handle all file/database writes
3. **No blocking** — app threads never wait for I/O operations
4. **Graceful shutdown** — signal I/O threads to exit in `PrepareForFini`, wait for them to finish, then do final cleanup in `Fini`

**Why this matters:**
- Instrumentation stays fast — app threads don't block on SQLite/file I/O
- No contention — only I/O threads touch the database/files
- Better throughput — background processing happens while tracing continues
- Clean shutdown — I/O threads flush remaining data before exit

In our case:
- Before: All threads tried to write to SQLite → `SQLITE_BUSY` errors and crashes
- After: All threads push to a queue → one background thread does all SQLite writes → no conflicts, smoother performance

This pattern is common in high-performance tracing tools: keep the hot path (instrumentation) fast, and offload expensive operations (I/O) to dedicated threads.
*/

#ifndef SQLITE_LOG_HANDLER_H
#define SQLITE_LOG_HANDLER_H
#include "pin.H"

#include <queue>
#include <set>
#include <map>
#include <vector>
#include <deque>
#include <string>
#include <ctime>
#include <cstring>
#include <sstream>
#include <iterator>
#include <sqlite3.h>

#include "Logger.h" // for LogHandler, LogLevel, logLevelToString
#include "Concurrency.h"

namespace tenet_tracer
{
namespace logging
{
    // Global queue for all trace entries - will be flushed to SQLite at program end
    struct GlobalTraceEntry {
        std::string tableName;
        long long timestamp;
        unsigned tid;
        unsigned long long pc;
        std::string registers;
        std::string mem_reads;
        std::string mem_writes;
    };
    
    // Global queue and lock - shared by all SqliteLogHandler instances
    extern std::deque<GlobalTraceEntry> g_trace_queue;
    extern tenet_tracer::concurrency::PinSpinLock g_trace_queue_lock;
    extern std::unique_ptr<tenet_tracer::concurrency::PinThread> g_flush_thread;  // Background flush thread
    extern tenet_tracer::concurrency::PinSemaphore g_flush_thread_exit_sem;  // Semaphore to signal background thread to exit
    
    // Per-thread buffer for batching entries before pushing to global queue
    struct ThreadLocalBuffer {
        std::vector<GlobalTraceEntry> entries;
        static const size_t BUFFER_SIZE = 1000;  // Flush when buffer reaches this size
        static const long long FLUSH_INTERVAL_SEC = 1;  // Flush every 1 second even if not full
        long long last_flush_time;  // Timestamp of last flush (seconds since epoch)
        
        ThreadLocalBuffer() : entries(), last_flush_time(static_cast<long long>(std::time(nullptr))) {
            entries.reserve(BUFFER_SIZE);
        }
        
        void flushToGlobalQueue() {
            if (entries.empty()) return;
            
            auto lock = g_trace_queue_lock.acquire_write();
            // Move all entries to global queue in one operation
            // Table names are already set when entries are created
            for (auto& entry : entries) {
                g_trace_queue.push_back(std::move(entry));
            }
            entries.clear();
            entries.reserve(BUFFER_SIZE);  // Re-reserve for next batch
            last_flush_time = static_cast<long long>(std::time(nullptr));  // Update flush time
        }
        
        bool shouldFlushByTime() const {
            long long now = static_cast<long long>(std::time(nullptr));
            return (now - last_flush_time) >= FLUSH_INTERVAL_SEC;
        }
    };
    
    // TLS key for per-thread buffers (initialized in cpp file)
    extern TLS_KEY g_buffer_tls_key;
    
    // Global SQLite shared state to avoid function-local statics (which pull in
    // MSVC thread-safe static initialization helpers like _Init_thread_header)
    struct SqliteSharedState {
        bool sqliteInitialized;
        std::map<std::string, sqlite3_stmt*> stmts;
        std::set<std::string> createdTables;

        SqliteSharedState() : sqliteInitialized(false) {}
    };

    // Defined in tenet_tracer.cpp
    extern SqliteSharedState g_sqlite_state;

    class SqliteLogHandler : public LogHandler
    {
    public:
        SqliteLogHandler(sqlite3* db, const std::string& tableName, size_t /*batchSize*/ = 100)
            : db_(db), tableName_(tableName) {
            // Just store table name - all writes go to global queue
            // Tables will be created when flushing
        }

        ~SqliteLogHandler() override {
            // Nothing to clean up - global queue will be flushed in Fini()
        }

        void log(const std::string& message, unsigned tid, LogLevel level) override {
            if (!db_) return;
            
            // Get or create thread-local buffer
            THREADID pinTid = PIN_ThreadId();
            ThreadLocalBuffer* buffer = static_cast<ThreadLocalBuffer*>(PIN_GetThreadData(g_buffer_tls_key, pinTid));
            if (!buffer) {
                buffer = new ThreadLocalBuffer();
                PIN_SetThreadData(g_buffer_tls_key, buffer, pinTid);
            }
            
            // Parse the trace message
            DbLogEntry entry;
            entry.timestamp = static_cast<long long>(std::time(nullptr));
            entry.tid = tid;

            parseTraceMessage(message, entry);

            // Add to thread-local buffer
            GlobalTraceEntry globalEntry;
            globalEntry.tableName = tableName_;
            globalEntry.timestamp = entry.timestamp;
            globalEntry.tid = entry.tid;
            globalEntry.pc = entry.pc;
            globalEntry.registers = entry.registers;
            globalEntry.mem_reads = entry.mem_reads;
            globalEntry.mem_writes = entry.mem_writes;
            
            buffer->entries.push_back(std::move(globalEntry));
            
            // Flush buffer to global queue if it's full or if enough time has passed
            // This ensures continuous flushing even with low activity
            if (buffer->entries.size() >= ThreadLocalBuffer::BUFFER_SIZE || buffer->shouldFlushByTime()) {
                buffer->flushToGlobalQueue();
            }
        }

        void close() override {
            // Nothing to do - global queue will be flushed in Fini()
        }
        
        // Result of flushing a batch
        struct FlushResult {
            size_t flushed;
            size_t available;
            double flush_time;  // Time taken to flush in seconds
            
            FlushResult() : flushed(0), available(0), flush_time(0.0) {}
            FlushResult(size_t f, size_t a, double t = 0.0) : flushed(f), available(a), flush_time(t) {}
            
            bool empty() const { return flushed == 0; }
        };
        
        // Static function to flush a batch from global queue to SQLite
        // Returns number of entries flushed and how many were available
        static FlushResult FlushBatchToDatabase(sqlite3* db, size_t batchSize = 10000, Logger* meta = nullptr) {
            if (!db) return FlushResult();
            
            // Get batch from queue
            std::vector<GlobalTraceEntry> batch;
            batch.reserve(batchSize);
            size_t available = 0;
            double queue_time = 0.0;
            
            {
                std::clock_t queue_start = std::clock();
                auto lock = g_trace_queue_lock.acquire_write();
                available = g_trace_queue.size();
                if (available > 0) {
                    size_t toTake = (available < batchSize) ? available : batchSize;
                    batch.reserve(toTake);
                    // Move elements from front of deque to batch, then pop them
                    for (size_t i = 0; i < toTake; ++i) {
                        batch.push_back(std::move(g_trace_queue.front()));
                        g_trace_queue.pop_front();
                    }
                }
                std::clock_t queue_end = std::clock();
                queue_time = static_cast<double>(queue_end - queue_start) / CLOCKS_PER_SEC;
            }
            
            if (batch.empty()) return FlushResult(0, available);
            
            // Start timing
            std::clock_t start_time = std::clock();
            
            // Set up SQLite for batch insert (only if not already done)
            if (!g_sqlite_state.sqliteInitialized) {
                sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
                sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
                g_sqlite_state.sqliteInitialized = true;
            }
            
            // Create tables and prepare statements for each unique table name
            
            sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
            
            size_t entriesProcessed = 0;
            for (const auto& entry : batch) {
                // Create table if needed (without index for now - indexes created at shutdown)
                if (g_sqlite_state.createdTables.find(entry.tableName) == g_sqlite_state.createdTables.end()) {
                    std::string createTableSql = 
                        R"(CREATE TABLE IF NOT EXISTS )" + entry.tableName + R"(_trace (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp INTEGER,
                            tid INTEGER,
                            pc INTEGER,
                            registers TEXT,
                            mem_reads TEXT,
                            mem_writes TEXT
                        );)";
                    sqlite3_exec(db, createTableSql.c_str(), nullptr, nullptr, nullptr);
                    
                    g_sqlite_state.createdTables.insert(entry.tableName);
                }
                
                // Get or create prepared statement
                if (g_sqlite_state.stmts.find(entry.tableName) == g_sqlite_state.stmts.end()) {
                    std::string insertSql = 
                        R"(INSERT INTO )" + entry.tableName + R"(_trace 
                        (timestamp, tid, pc, registers, mem_reads, mem_writes) 
                        VALUES (?, ?, ?, ?, ?, ?);)";
                    sqlite3_stmt* stmt = nullptr;
                    if (sqlite3_prepare_v2(db, insertSql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
                        g_sqlite_state.stmts[entry.tableName] = stmt;
                    }
                }
                
                // Insert entry
                sqlite3_stmt* stmt = g_sqlite_state.stmts[entry.tableName];
                if (stmt) {
                    sqlite3_bind_int64(stmt, 1, entry.timestamp);
                    sqlite3_bind_int(stmt, 2, entry.tid);
                    sqlite3_bind_int64(stmt, 3, entry.pc);
                    sqlite3_bind_text(stmt, 4, entry.registers.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 5, entry.mem_reads.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 6, entry.mem_writes.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_step(stmt);
                    sqlite3_reset(stmt);
                }
                
                entriesProcessed++;
            }
            
            sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
            
            // Calculate elapsed time
            std::clock_t end_time = std::clock();
            double elapsed_seconds = static_cast<double>(end_time - start_time) / CLOCKS_PER_SEC;
            
            FlushResult result(entriesProcessed, available, elapsed_seconds);
            
            // Log statistics if meta logger is provided
            if (meta && result.flushed > 0) {
                if (result.available > 0) {
                    meta->infof("Flushed %zu / %zu entries (%.1f%%) in %.2f seconds (queue: %.3fs)", 
                               result.flushed, result.available,
                               (result.flushed * 100.0) / result.available,
                               result.flush_time, queue_time);
                } else {
                    meta->infof("Flushed %zu entries in %.2f seconds (queue: %.3fs)", 
                               result.flushed, result.flush_time, queue_time);
                }
            }
            
            return result;
        }
        
        // Static function to flush entire queue to SQLite (called from Fini())
        static void FlushQueueToDatabase(sqlite3* db, Logger* meta = nullptr) {
            if (!db) return;
            
            if (meta) meta->info("Flushing remaining trace queue to SQLite database...");
            
            // Keep flushing batches until queue is empty
            // FlushBatchToDatabase will handle the logging
            while (true) {
                FlushResult result = FlushBatchToDatabase(db, 100000, meta);
                if (result.empty()) break;
            }
        }
        
        // Start the background flush thread
        static void StartBackgroundFlushThread(sqlite3* db, Logger* meta = nullptr) {
            if (!db) return;
            
            bool alreadyStarted;
            {
                auto lock = g_trace_queue_lock.acquire_read();
                alreadyStarted = (g_flush_thread != nullptr);
            }
            
            if (alreadyStarted) return;
            
            // Create PinThread with lambda that captures db and meta
            auto thread = std::unique_ptr<tenet_tracer::concurrency::PinThread>(
                new tenet_tracer::concurrency::PinThread([db, meta]() {
                    size_t batchSize = 10 * 1024;  // Start with 10k entries (will adaptively grow)
                    const size_t minBatchSize = 1 * 1024 * 1024;  // 1M entries
                    const size_t maxBatchSize = 3 * 1024 * 1024;  // Cap at 3M to avoid long lock holds
                    auto batch_threshold_sec = 0.05;
                    while (true) {
                        // Check if we should exit
                        if (g_flush_thread_exit_sem.is_set()) {
                            // Flush any remaining entries before exiting
                            size_t effectiveBatchSize = (batchSize > maxBatchSize) ? maxBatchSize : batchSize;
                            FlushResult result = FlushBatchToDatabase(db, effectiveBatchSize, meta);
                            while (!result.empty()) {
                                // Keep flushing until empty
                                if (result.flush_time <= batch_threshold_sec) {
                                    batchSize = min(
                                        (batchSize >= minBatchSize) ? (batchSize + minBatchSize) : (batchSize * 10),
                                        maxBatchSize
                                    );
                                }
                                effectiveBatchSize = (batchSize > maxBatchSize) ? maxBatchSize : batchSize;
                                result = FlushBatchToDatabase(db, effectiveBatchSize, meta);
                            }
                            
                            // Create indexes for all tables after all data is flushed (much faster)
                            if (meta && !g_sqlite_state.createdTables.empty()) {
                                meta->infof("Creating indexes for %zu trace tables...", g_sqlite_state.createdTables.size());
                                
                                // Optimize SQLite for index creation
                                sqlite3_exec(db, "PRAGMA cache_size = -512000;", nullptr, nullptr, nullptr);  // 512MB cache
                                sqlite3_exec(db, "PRAGMA temp_store = MEMORY;", nullptr, nullptr, nullptr);
                                sqlite3_exec(db, "PRAGMA synchronous = OFF;", nullptr, nullptr, nullptr);  // Faster for index creation
                                
                                std::clock_t index_start = std::clock();
                                size_t table_count = 0;
                                for (const auto& tableName : g_sqlite_state.createdTables) {
                                    std::clock_t table_start = std::clock();
                                    
                                    // Get row count for progress info
                                    std::string countSql = "SELECT COUNT(*) FROM " + tableName + "_trace;";
                                    sqlite3_stmt* countStmt = nullptr;
                                    long long rowCount = 0;
                                    if (sqlite3_prepare_v2(db, countSql.c_str(), -1, &countStmt, nullptr) == SQLITE_OK) {
                                        if (sqlite3_step(countStmt) == SQLITE_ROW) {
                                            rowCount = sqlite3_column_int64(countStmt, 0);
                                        }
                                        sqlite3_finalize(countStmt);
                                    }
                                    
                                    if (meta && rowCount > 0) {
                                        meta->infof("  [%zu/%zu] Indexing %s (%lld rows)...", 
                                                   table_count + 1, g_sqlite_state.createdTables.size(), 
                                                   tableName.c_str(), rowCount);
                                    }
                                    
                                    std::string createIndexSql = 
                                        R"(CREATE INDEX IF NOT EXISTS idx_)" + tableName + R"(_trace_tid_ts 
                                        ON )" + tableName + R"(_trace(tid, timestamp);)";
                                    sqlite3_exec(db, createIndexSql.c_str(), nullptr, nullptr, nullptr);
                                    
                                    std::clock_t table_end = std::clock();
                                    double table_time = static_cast<double>(table_end - table_start) / CLOCKS_PER_SEC;
                                    table_count++;
                                    if (meta) {
                                        meta->infof("  [%zu/%zu] Indexed %s (%.2fs)", 
                                                   table_count, g_sqlite_state.createdTables.size(), 
                                                   tableName.c_str(), table_time);
                                    }
                                }
                                
                                // Restore normal settings
                                sqlite3_exec(db, "PRAGMA synchronous = NORMAL;", nullptr, nullptr, nullptr);
                                
                                std::clock_t index_end = std::clock();
                                double total_time = static_cast<double>(index_end - index_start) / CLOCKS_PER_SEC;
                                if (meta) meta->infof("Index creation complete (%.2fs total)", total_time);
                            }
                            
                            break;
                        }

                        // Flush a batch with current batch size (capped at max)
                        size_t effectiveBatchSize = (batchSize > maxBatchSize) ? maxBatchSize : batchSize;
                        FlushResult result = FlushBatchToDatabase(db, effectiveBatchSize, meta);
                        
                        // Adaptive batch sizing: if flush was fast, increase batch size
                        if (!result.empty() && result.flush_time <= batch_threshold_sec) {
                            batchSize = min(
                                (batchSize >= minBatchSize) ? (batchSize + minBatchSize) : (batchSize * 10),
                                maxBatchSize
                            );
                        }
                        
                        // If queue is empty, wait briefly before checking again
                        if (result.empty()) {
                            g_flush_thread_exit_sem.wait_timed(100);
                        }
                    }
                })
            );
            tenet_tracer::logging::winconsole::debugLog("about to start the thread!");
            // Start the thread
            thread->run();

            // Store the thread instance
            {
                auto lock = g_trace_queue_lock.acquire_write();
                if (thread->thread_id() != INVALID_THREADID) {
                    g_flush_thread = std::move(thread);
                } else {
                    if (meta) meta->error("Failed to spawn background flush thread");
                }
            }
            tenet_tracer::logging::winconsole::debugLog("thread started!");
        }
        
        // Flush all thread-local buffers to global queue (called before shutdown)
        static void FlushAllThreadBuffers() {
            // Note: We can't easily iterate all threads, so we rely on threads flushing
            // their own buffers when they exit. This function is a placeholder for
            // potential future enhancement if needed.
        }
        
        // Stop the background flush thread (called from PrepareForFini)
        static void StopBackgroundFlushThread() {
            std::unique_ptr<tenet_tracer::concurrency::PinThread> thread;
            {
                auto lock = g_trace_queue_lock.acquire_write();
                if (!g_flush_thread) {
                    return;
                }
                thread = std::move(g_flush_thread);
            }
            
            // Signal thread to exit via semaphore
            g_flush_thread_exit_sem.set();
            tenet_tracer::logging::winconsole::debugLog("waiting 4 thread to finish!");
            // Wait for thread to finish
            thread->wait();
        }

    private:
        struct DbLogEntry
        {
            long long timestamp;
            unsigned tid;
            unsigned long long pc;
            std::string registers;
            std::string mem_reads;
            std::string mem_writes;
        };

        static std::string escapeJsonString(const std::string& str) {
            std::string result;
            result.reserve(str.size() + 10);
            for (size_t i = 0; i < str.size(); ++i) {
                char c = str[i];
                if (c == '"') {
                    result += "\\\"";
                } else if (c == '\\') {
                    result += "\\\\";
                } else if (c == '\b') {
                    result += "\\b";
                } else if (c == '\f') {
                    result += "\\f";
                } else if (c == '\n') {
                    result += "\\n";
                } else if (c == '\r') {
                    result += "\\r";
                } else if (c == '\t') {
                    result += "\\t";
                } else if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    result += buf;
                } else {
                    result += c;
                }
            }
            return result;
        }

        void parseTraceMessage(const std::string& message, DbLogEntry& entry) {
            entry.pc = 0;
            entry.registers = "{}";
            entry.mem_reads = "[]";
            entry.mem_writes = "[]";

            if (message.empty()) return;

            std::vector<std::pair<std::string, std::string> > regs;
            std::vector<std::pair<std::string, std::string> > reads;
            std::vector<std::pair<std::string, std::string> > writes;

            size_t pos = 0;
            while (pos < message.size()) {
                size_t eqPos = message.find('=', pos);
                if (eqPos == std::string::npos) break;

                size_t commaPos = message.find(',', eqPos);
                if (commaPos == std::string::npos) commaPos = message.size();

                std::string key = message.substr(pos, eqPos - pos);
                std::string value = message.substr(eqPos + 1, commaPos - eqPos - 1);

                if (key == "rip" || key == "eip") {
                    entry.pc = strtoull(value.c_str(), nullptr, 16);
                } else if (key == "mr") {
                    size_t colonPos = value.find(':');
                    if (colonPos != std::string::npos) {
                        std::string addr = value.substr(0, colonPos);
                        std::string data = value.substr(colonPos + 1);
                        reads.push_back(std::make_pair(addr, data));
                    }
                } else if (key == "mw") {
                    size_t colonPos = value.find(':');
                    if (colonPos != std::string::npos) {
                        std::string addr = value.substr(0, colonPos);
                        std::string data = value.substr(colonPos + 1);
                        writes.push_back(std::make_pair(addr, data));
                    }
                } else {
                    regs.push_back(std::make_pair(key, value));
                }

                pos = commaPos + 1;
            }

            // Build registers JSON object
            if (regs.empty()) {
                entry.registers = "{}";
            } else {
                std::string regsJson = "{";
                for (size_t i = 0; i < regs.size(); ++i) {
                    if (i > 0) regsJson += ",";
                    regsJson += "\"";
                    regsJson += escapeJsonString(regs[i].first);
                    regsJson += "\":\"";
                    regsJson += escapeJsonString(regs[i].second);
                    regsJson += "\"";
                }
                regsJson += "}";
                entry.registers = regsJson;
            }

            // Build reads JSON array
            if (reads.empty()) {
                entry.mem_reads = "[]";
            } else {
                std::string readsJson = "[";
                for (size_t i = 0; i < reads.size(); ++i) {
                    if (i > 0) readsJson += ",";
                    readsJson += "{\"addr\":\"";
                    readsJson += escapeJsonString(reads[i].first);
                    readsJson += "\",\"data\":\"";
                    readsJson += escapeJsonString(reads[i].second);
                    readsJson += "\"}";
                }
                readsJson += "]";
                entry.mem_reads = readsJson;
            }

            // Build writes JSON array
            if (writes.empty()) {
                entry.mem_writes = "[]";
            } else {
                std::string writesJson = "[";
                for (size_t i = 0; i < writes.size(); ++i) {
                    if (i > 0) writesJson += ",";
                    writesJson += "{\"addr\":\"";
                    writesJson += escapeJsonString(writes[i].first);
                    writesJson += "\",\"data\":\"";
                    writesJson += escapeJsonString(writes[i].second);
                    writesJson += "\"}";
                }
                writesJson += "]";
                entry.mem_writes = writesJson;
            }


        }

        sqlite3* db_;
        std::string tableName_;
    };


    // Allow chained style: LoggerBuilder().addFileHandler(...), then .addSqliteHandler(...)
    // by adding a method via ADL-like helper:
    struct LoggerBuilderSqliteMixin
    {
        LoggerBuilder& builder;

        LoggerBuilderSqliteMixin(LoggerBuilder& b) : builder(b) {}

        LoggerBuilder& AddSqliteHandler(sqlite3* db, const std::string& tableName, size_t batchSize = 100) const {
            if (db) builder.addHandler<SqliteLogHandler>(db, tableName, batchSize);
            return builder;
        }
    };

    // Convenience function to start a chain that includes sqlite methods if included:
    inline LoggerBuilderSqliteMixin WithSqlite(LoggerBuilder& b) {
        return LoggerBuilderSqliteMixin{b};
    }
} // namespace logging
} // namespace tenet_tracer


#endif // SQLITE_LOG_HANDLER_H

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
   }
   #endif

// Query examples after tracing:

// List all tables
sqlite3 tenet_trace.db ".tables"

// Show schema
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

#include <queue>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <ctime>
#include <cstring>
#include <sstream>

#include "pin.H"
#include <sqlite3.h>

#include "Logger.h" // for LogHandler, LogLevel, logLevelToString
#include "PinLocker.h"

namespace tenet_tracer
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
    extern std::vector<GlobalTraceEntry> g_trace_queue;
    extern PinSpinLock g_trace_queue_lock;
    extern PIN_THREAD_UID g_flush_thread_uid;  // Background flush thread UID
    extern bool g_flush_thread_should_exit;    // Flag to signal background thread to exit
    
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
        SqliteLogHandler(sqlite3* db, const std::string& tableName, size_t batchSize = 100)
            : db_(db), tableName_(tableName) {
            // Just store table name - all writes go to global queue
            // Tables will be created when flushing
        }

        ~SqliteLogHandler() override {
            // Nothing to clean up - global queue will be flushed in Fini()
        }

        void log(const std::string& message, unsigned tid, LogLevel level) override {
            if (!db_) return;

            // Parse the trace message
            DbLogEntry entry;
            entry.timestamp = static_cast<long long>(std::time(nullptr));
            entry.tid = tid;
            parseTraceMessage(message, entry);
            
            // Push to global queue
            GlobalTraceEntry globalEntry;
            globalEntry.tableName = tableName_;
            globalEntry.timestamp = entry.timestamp;
            globalEntry.tid = entry.tid;
            globalEntry.pc = entry.pc;
            globalEntry.registers = entry.registers;
            globalEntry.mem_reads = entry.mem_reads;
            globalEntry.mem_writes = entry.mem_writes;
            
            {
                auto lock = g_trace_queue_lock.acquire_write();
                g_trace_queue.push_back(globalEntry);
            }
        }

        void close() override {
            // Nothing to do - global queue will be flushed in Fini()
        }
        
        // Static function to flush a batch from global queue to SQLite
        // Returns number of entries flushed
        static size_t FlushBatchToDatabase(sqlite3* db, size_t batchSize = 10000) {
            if (!db) return 0;
            
            // Get batch from queue
            std::vector<GlobalTraceEntry> batch;
            batch.reserve(batchSize);
            
            {
                auto lock = g_trace_queue_lock.acquire_write();
                size_t available = g_trace_queue.size();
                if (available > 0) {
                    size_t toTake = (available < batchSize) ? available : batchSize;
                    batch.assign(g_trace_queue.begin(), g_trace_queue.begin() + toTake);
                    g_trace_queue.erase(g_trace_queue.begin(), g_trace_queue.begin() + toTake);
                }
            }
            
            if (batch.empty()) return 0;
            
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
                // Create table if needed
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
                    
                    std::string createIndexSql = 
                        R"(CREATE INDEX IF NOT EXISTS idx_)" + entry.tableName + R"(_trace_tid_ts 
                        ON )" + entry.tableName + R"(_trace(tid, timestamp);)";
                    sqlite3_exec(db, createIndexSql.c_str(), nullptr, nullptr, nullptr);
                    
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
                
                // Progress reporting every 50,000 entries
                entriesProcessed++;
                if (entriesProcessed % 50000 == 0) {
                    fprintf(stderr, "  Flushed %zu / %zu entries (%.1f%%)\n", 
                            entriesProcessed, batch.size(),
                            (entriesProcessed * 100.0) / batch.size());
                }
            }
            
            sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
            
            return entriesProcessed;
        }
        
        // Static function to flush entire queue to SQLite (called from Fini())
        static void FlushQueueToDatabase(sqlite3* db) {
            if (!db) return;
            
            fprintf(stderr, "Flushing remaining trace queue to SQLite database...\n");
            size_t totalFlushed = 0;
            
            // Keep flushing batches until queue is empty
            while (true) {
                size_t flushed = FlushBatchToDatabase(db, 10000);
                if (flushed == 0) break;
                totalFlushed += flushed;
                if (totalFlushed % 50000 == 0) {
                    fprintf(stderr, "  Flushed %zu entries so far...\n", totalFlushed);
                }
            }
            
            // Clean up static statements (shared with FlushBatchToDatabase)
            // Note: statements are cleaned up in FlushBatchToDatabase's static variables
            // We'll finalize them here by accessing the static map
            // Actually, they'll persist and be cleaned up automatically at program exit
            
            fprintf(stderr, "  Wrote %zu total trace entries\n", totalFlushed);
        }
        
        // Background thread that periodically flushes batches
        static VOID BackgroundFlushThread(VOID* arg) {
            sqlite3* db = static_cast<sqlite3*>(arg);
            if (!db) return;
            
            // Process batches every ~100ms
            while (true) {
                PIN_Sleep(100); // Sleep 100ms
                
                // Check if we should exit
                bool shouldExit;
                {
                    auto lock = g_trace_queue_lock.acquire_read();
                    shouldExit = g_flush_thread_should_exit;
                }
                
                if (shouldExit) {
                    // Flush any remaining entries before exiting
                    while (FlushBatchToDatabase(db, 10000) > 0) {
                        // Keep flushing until empty
                    }
                    break;
                }
                
                // Flush a batch (10k entries at a time)
                size_t flushed = FlushBatchToDatabase(db, 10000);
                if (flushed > 0 && flushed >= 10000) {
                    fprintf(stderr, "  Background flush: %zu entries\n", flushed);
                }
            }
            
            PIN_ExitThread(0);
        }
        
        // Start the background flush thread
        static void StartBackgroundFlushThread(sqlite3* db) {
            if (!db) return;
            
            bool alreadyStarted;
            {
                auto lock = g_trace_queue_lock.acquire_read();
                alreadyStarted = (g_flush_thread_uid != 0);
            }
            
            if (alreadyStarted) return;
            
            THREADID threadId = PIN_SpawnInternalThread(BackgroundFlushThread, db, 0, &g_flush_thread_uid);
            if (threadId == INVALID_THREADID) {
                fprintf(stderr, "Failed to spawn background flush thread\n");
                auto lock = g_trace_queue_lock.acquire_write();
                g_flush_thread_uid = 0;
            }
        }
        
        // Stop the background flush thread (called from PrepareForFini)
        static void StopBackgroundFlushThread() {
            PIN_THREAD_UID uid;
            {
                auto lock = g_trace_queue_lock.acquire_read();
                uid = g_flush_thread_uid;
            }
            
            if (uid == 0) return;
            
            // Signal thread to exit
            {
                auto lock = g_trace_queue_lock.acquire_write();
                g_flush_thread_should_exit = true;
            }
            
            // Wait for thread to finish
            INT32 exitCode;
            PIN_WaitForThreadTermination(uid, PIN_INFINITE_TIMEOUT, &exitCode);
            
            {
                auto lock = g_trace_queue_lock.acquire_write();
                g_flush_thread_uid = 0;
            }
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

        void parseTraceMessage(const std::string& message, DbLogEntry& entry) {
            // Parse format: reg=0xval,reg=0xval,rip=0xval,mr=0xaddr:bytes,mw=0xaddr:bytes
            entry.pc = 0;
            entry.registers = "{}";
            entry.mem_reads = "[]";
            entry.mem_writes = "[]";

            if (message.empty()) return;

            std::ostringstream regs;
            std::ostringstream reads;
            std::ostringstream writes;
            
            regs << "{";
            reads << "[";
            writes << "[";
            
            bool firstReg = true;
            bool firstRead = true;
            bool firstWrite = true;

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
                    // Memory read: mr=0xaddr:hexbytes
                    size_t colonPos = value.find(':');
                    if (colonPos != std::string::npos) {
                        std::string addr = value.substr(0, colonPos);
                        std::string data = value.substr(colonPos + 1);
                        if (!firstRead) reads << ",";
                        reads << "{\"addr\":\"" << addr << "\",\"data\":\"" << data << "\"}";
                        firstRead = false;
                    }
                } else if (key == "mw") {
                    // Memory write: mw=0xaddr:hexbytes
                    size_t colonPos = value.find(':');
                    if (colonPos != std::string::npos) {
                        std::string addr = value.substr(0, colonPos);
                        std::string data = value.substr(colonPos + 1);
                        if (!firstWrite) writes << ",";
                        writes << "{\"addr\":\"" << addr << "\",\"data\":\"" << data << "\"}";
                        firstWrite = false;
                    }
                } else {
                    // Regular register
                    if (!firstReg) regs << ",";
                    regs << "\"" << key << "\":\"" << value << "\"";
                    firstReg = false;
                }

                pos = commaPos + 1;
            }

            regs << "}";
            reads << "]";
            writes << "]";

            entry.registers = regs.str();
            entry.mem_reads = reads.str();
            entry.mem_writes = writes.str();
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
} // namespace tenet_tracer


#endif // SQLITE_LOG_HANDLER_H

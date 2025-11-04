//
// Logger.h
//
// A simple header‑only logger that supports writing messages to a file with
// optional log rotation, per‑thread file suffixes, and SQLite3 insertion.
//
// The logger is designed to be C++14 compatible (for PIN 3.31) but will
// compile unmodified under C++17 (for PIN 4.0). It is inspired by the
// logging approach used in the pintenet tracer and influenced by third‑party
// examples such as the DaveSaveEd logger and sqlite_orm_lite's logger.  The
// rotation logic is intentionally simple: when the file grows beyond a
// configurable maximum size, it is renamed to `.old` and a new file is
// created.  Per‑thread suffixes are applied by inserting the thread id
// immediately before the file extension.  SQLite insertion is optional and
// compiled only if `USE_SQLITE3` is defined.
//
// To use SQLite logging, define `USE_SQLITE3` before including this header
// and link against sqlite3.  Call setSqliteDatabase() with an open database
// and table name.  Each logged message will be inserted into the given
// table with three columns: `time` (ISO‑8601 string), `tid` (integer), and
// `message` (text).
//

#ifndef LOGGER_H
#define LOGGER_H

#include <fstream>
#include <sstream>
#include <string>
#include <mutex>
#include <ctime>
#include <cstdio> // for rename/remove

// Additional headers for asynchronous database logging
#include <condition_variable>
#include <queue>
#include <thread>
#include <set>

// SQLite integration is optional.  If you want to log to a database,
// include <sqlite3.h> and define USE_SQLITE3 before including this header.
#ifdef USE_SQLITE3
#include <sqlite3.h>
#endif

namespace tinytrace
{

    class Logger
    {
    public:
        // Construct a logger.  The base filename should include the desired
        // extension (for example, "trace.log").  When appendThreadId is true,
        // the thread id will be inserted before the file extension.  maxFileSize
        // specifies the maximum size in bytes before the log is rotated.
        Logger(const std::string &baseFilename,
               std::size_t maxFileSize = 10 * 1024 * 1024,
               bool appendThreadId = false)
            : baseFilename_(baseFilename),
              maxFileSize_(maxFileSize),
              appendThreadId_(appendThreadId),
              currentThreadId_(static_cast<unsigned>(-1)),
              currentFilename_(""),
              file_()
#ifdef USE_SQLITE3
              ,
              db_(nullptr),
              tableName_("")
#endif
        {
        }

        // Non‑copyable.
        Logger(const Logger &) = delete;
        Logger &operator=(const Logger &) = delete;

        // Move constructor/assignment allowed.
        Logger(Logger &&other) noexcept
            : baseFilename_(other.baseFilename_),
              maxFileSize_(other.maxFileSize_),
              appendThreadId_(other.appendThreadId_),
              currentThreadId_(other.currentThreadId_),
              currentFilename_(other.currentFilename_),
              file_(std::move(other.file_))
#ifdef USE_SQLITE3
              ,
              db_(other.db_),
              tableName_(other.tableName_)
#endif
        {
            // leave other in a valid state
            other.currentThreadId_ = static_cast<unsigned>(-1);
            other.currentFilename_.clear();
#ifdef USE_SQLITE3
            other.db_ = nullptr;
            other.tableName_.clear();
#endif
        }

        Logger &operator=(Logger &&other) noexcept
        {
            if (this != &other)
            {
                std::lock_guard<std::mutex> lock(mtx_);
                close();
                baseFilename_ = other.baseFilename_;
                maxFileSize_ = other.maxFileSize_;
                appendThreadId_ = other.appendThreadId_;
                currentThreadId_ = other.currentThreadId_;
                currentFilename_ = other.currentFilename_;
                file_ = std::move(other.file_);
#ifdef USE_SQLITE3
                db_ = other.db_;
                tableName_ = other.tableName_;
                other.db_ = nullptr;
                other.tableName_.clear();
#endif
                other.currentThreadId_ = static_cast<unsigned>(-1);
                other.currentFilename_.clear();
            }
            return *this;
        }

        ~Logger()
        {
            close();
        }

        // Assign a thread id.  When appendThreadId is true, this thread id will
        // be appended to the log filename.  Calling this multiple times will
        // reopen the file for the new thread.
        void setThreadId(unsigned tid)
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (currentThreadId_ != tid)
            {
                currentThreadId_ = tid;
                currentFilename_.clear();
                openFile();
            }
        }

#ifdef USE_SQLITE3
        // Configure SQLite logging.  Supply an open sqlite3 database handle and
        // the name of a table into which log messages will be inserted.  A
        // corresponding table will be created if it does not exist.  Each call
        // returns true on success or false on failure.
        bool setSqliteDatabase(sqlite3 *db, const std::string &tableName)
        {
            std::lock_guard<std::mutex> lock(mtx_);
            db_ = db;
            tableName_ = tableName;
            if (!db_)
                return false;
            // Create table if needed.  We define three columns: time (TEXT),
            // tid (INTEGER), and message (TEXT).  The time column will store
            // ISO‑8601 strings.
            std::ostringstream oss;
            oss << "CREATE TABLE IF NOT EXISTS " << tableName_ << " ("
                                                                  "time TEXT, tid INTEGER, message TEXT);";
            char *errMsg = nullptr;
            int rc = sqlite3_exec(db_, oss.str().c_str(), nullptr, nullptr, &errMsg);
            if (rc != SQLITE_OK)
            {
                if (errMsg)
                    sqlite3_free(errMsg);
                db_ = nullptr;
                return false;
            }
            // Start an asynchronous worker thread to handle database inserts.
            // This ensures that log() can enqueue messages quickly without
            // incurring the cost of sqlite operations on the hot path.  We
            // only create the worker once; subsequent calls will reuse the
            // existing thread.
            if (!dbThread_.joinable())
            {
                dbStop_ = false;
                dbThread_ = std::thread(&Logger::dbWorker, this);
            }
            return true;
        }
#endif

        // Write a message to the log.  A newline will be appended
        // automatically.  When SQLite logging is enabled, the message will
        // also be inserted into the configured table.
        void log(const std::string &message)
        {
            std::lock_guard<std::mutex> lock(mtx_);
            openFile();
            if (file_.is_open())
            {
                file_ << message << '\n';
                file_.flush();
                rotateIfNeeded();
            }
#ifdef USE_SQLITE3
            if (db_)
            {
                // Prepare time string (UTC ISO‑8601)
                char timeBuf[32];
                std::time_t t = std::time(nullptr);
                std::tm *tmInfo = std::gmtime(&t);
                if (tmInfo)
                {
                    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%dT%H:%M:%SZ", tmInfo);
                }
                else
                {
                    std::strncpy(timeBuf, "1970-01-01T00:00:00Z", sizeof(timeBuf));
                    timeBuf[sizeof(timeBuf) - 1] = '\0';
                }
                // Escape single quotes in message for SQL
                std::string escMsg;
                escMsg.reserve(message.size());
                for (std::size_t i = 0; i < message.size(); ++i)
                {
                    char c = message[i];
                    if (c == '\'')
                        escMsg += "''";
                    else
                        escMsg += c;
                }
                // Create a log entry and enqueue it
                DbLogEntry entry;
                entry.time = timeBuf;
                entry.tid = currentThreadId_;
                entry.message = escMsg;
                {
                    std::lock_guard<std::mutex> lk(queueMutex_);
                    dbQueue_.push(entry);
                }
                dbCond_.notify_one();
            }
#endif
        }

    private:
        std::string baseFilename_;
        std::size_t maxFileSize_;
        bool appendThreadId_;
        unsigned currentThreadId_;
        std::string currentFilename_;
        std::ofstream file_;
        std::mutex mtx_;
#ifdef USE_SQLITE3
        sqlite3 *db_;
        std::string tableName_;
#endif

#ifdef USE_SQLITE3
        // Structure representing a log entry queued for database insertion.
        struct DbLogEntry
        {
            std::string time;
            unsigned tid;
            std::string message;
        };

        // Queue and synchronization primitives for asynchronous DB insertion.
        std::queue<DbLogEntry> dbQueue_;
        std::mutex queueMutex_;
        std::condition_variable dbCond_;
        std::thread dbThread_;
        bool dbStop_ = false;

        // Keep track of which per‑thread tables have been created to avoid
        // redundant CREATE TABLE statements.
        std::set<std::string> createdTables_;

        // Worker thread function that drains the queue and performs inserts.
        void dbWorker()
        {
            while (true)
            {
                DbLogEntry entry;
                {
                    std::unique_lock<std::mutex> lk(queueMutex_);
                    dbCond_.wait(lk, [this]
                                 { return dbStop_ || !dbQueue_.empty(); });
                    if (dbStop_ && dbQueue_.empty())
                    {
                        break;
                    }
                    entry = dbQueue_.front();
                    dbQueue_.pop();
                }
                // Ensure the raw table exists
                std::string rawTable = tableName_ + "_raw";
                {
                    std::ostringstream createSql;
                    createSql << "CREATE TABLE IF NOT EXISTS " << rawTable
                              << " (time TEXT, tid INTEGER, message TEXT);";
                    sqlite3_exec(db_, createSql.str().c_str(), nullptr, nullptr, nullptr);
                }
                // Insert into raw table
                {
                    std::ostringstream insertSql;
                    insertSql << "INSERT INTO " << rawTable
                              << " (time, tid, message) VALUES ('" << entry.time << "', "
                              << entry.tid << ", '" << entry.message << "');";
                    sqlite3_exec(db_, insertSql.str().c_str(), nullptr, nullptr, nullptr);
                }
                // Determine per‑thread table name and create if necessary
                std::ostringstream tblName;
                tblName << tableName_ << "_" << entry.tid;
                std::string perThreadTable = tblName.str();
                if (createdTables_.insert(perThreadTable).second)
                {
                    std::ostringstream createSql;
                    createSql << "CREATE TABLE IF NOT EXISTS " << perThreadTable
                              << " (time TEXT, tid INTEGER, message TEXT);";
                    sqlite3_exec(db_, createSql.str().c_str(), nullptr, nullptr, nullptr);
                }
                // Insert into per‑thread table
                {
                    std::ostringstream insertSql;
                    insertSql << "INSERT INTO " << perThreadTable
                              << " (time, tid, message) VALUES ('" << entry.time << "', "
                              << entry.tid << ", '" << entry.message << "');";
                    sqlite3_exec(db_, insertSql.str().c_str(), nullptr, nullptr, nullptr);
                }
            }
        }
#endif // USE_SQLITE3
#endif

        // Ensure the file is open for writing.  If the filename has changed
        // because of a new thread id, the file will be reopened.  The full
        // filename with thread id appended is cached in currentFilename_.
        void openFile()
        {
            // Determine target filename
            std::string filename = baseFilename_;
            if (appendThreadId_ && currentThreadId_ != static_cast<unsigned>(-1))
            {
                // Insert thread id before extension
                std::size_t pos = filename.find_last_of('.');
                if (pos != std::string::npos)
                {
                    filename.insert(pos, "_" + std::to_string(currentThreadId_));
                }
                else
                {
                    filename += "_" + std::to_string(currentThreadId_);
                }
            }
            // If file is already open for this filename, do nothing
            if (file_.is_open() && currentFilename_ == filename)
            {
                return;
            }
            // Close previous file if any
            if (file_.is_open())
            {
                file_.close();
            }
            currentFilename_ = filename;
            // Open new file in append mode so we don't clobber existing logs
            file_.open(currentFilename_.c_str(), std::ios::out | std::ios::app);
            // No further action needed if open fails; log() will silently drop messages
        }

        // Rotate the log if it exceeds maxFileSize_.  The current file is closed,
        // renamed to `<name>.old`, and a new file is opened.
        void rotateIfNeeded()
        {
            if (!file_.is_open())
                return;
            std::streampos pos = file_.tellp();
            if (pos < 0)
                return;
            if (static_cast<std::size_t>(pos) >= maxFileSize_)
            {
                file_.close();
                // Build rotated filename
                std::string rotated = currentFilename_ + ".old";
                // Remove existing .old file if present
                std::remove(rotated.c_str());
                std::rename(currentFilename_.c_str(), rotated.c_str());
                // Reopen original log file
                file_.open(currentFilename_.c_str(), std::ios::out | std::ios::trunc);
            }
        }

        void close()
        {
#ifdef USE_SQLITE3
            // Stop the DB worker thread.  Setting the flag and notifying
            // ensures the worker wakes up and exits once the queue is drained.
            if (db_ && dbThread_.joinable())
            {
                {
                    std::lock_guard<std::mutex> qlk(queueMutex_);
                    dbStop_ = true;
                }
                dbCond_.notify_one();
                dbThread_.join();
            }
#endif
            if (file_.is_open())
            {
                file_.close();
            }
        }
    };

} // namespace tinytrace

#endif // LOGGER_H
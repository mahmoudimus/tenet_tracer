#ifndef SQLITE_LOG_HANDLER_H
#define SQLITE_LOG_HANDLER_H

#include <condition_variable>
#include <mutex>
#include <queue>
#include <set>
#include <string>
#include <thread>
#include <ctime>
#include <cstring>
#include <sstream>

#include <sqlite3.h>

#include "Logger.h" // for LogHandler, LogLevel, logLevelToString

namespace tenet_tracer
{
    class SqliteLogHandler : public LogHandler
    {
    public:
        SqliteLogHandler(sqlite3* db, const std::string& tableName)
            : db_(db), tableName_(tableName) {
            if (!db_) return;

            // Create raw table
            std::ostringstream oss;
            oss << "CREATE TABLE IF NOT EXISTS " << tableName_ << "_raw ("
                << "time TEXT, tid INTEGER, level TEXT, message TEXT);";
            sqlite3_exec(db_, oss.str().c_str(), nullptr, nullptr, nullptr);

            // Start async worker
            dbThread_ = std::thread(&SqliteLogHandler::dbWorker, this);
        }

        ~SqliteLogHandler() override {
            SqliteLogHandler::close();
        }

        void log(const std::string& message, unsigned tid, LogLevel level) override {
            if (!db_) return;

            // ISO-8601 UTC time
            char timeBuf[32];
            std::time_t t = std::time(nullptr);
            std::tm* tmInfo = std::gmtime(&t);
            if (tmInfo) {
                std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%dT%H:%M:%SZ", tmInfo);
            }
            else {
                std::strncpy(timeBuf, "1970-01-01T00:00:00Z", sizeof(timeBuf));
                timeBuf[sizeof(timeBuf) - 1] = '\0';
            }

            // Escape single quotes (very simple escaping for demo)
            std::string escMsg;
            escMsg.reserve(message.size());
            for (const char c : message) {
                escMsg += (c == '\'') ? "''" : std::string(1, c);
            }

            DbLogEntry entry;
            entry.time = timeBuf;
            entry.tid = tid;
            entry.level = logLevelToString(level);
            entry.message = escMsg;

            {
                std::lock_guard<std::mutex> lk(queueMutex_);
                dbQueue_.push(std::move(entry));
            }
            dbCond_.notify_one();
        }

        void close() override {
            if (dbThread_.joinable()) {
                {
                    std::lock_guard<std::mutex> lk(queueMutex_);
                    dbStop_ = true;
                }
                dbCond_.notify_one();
                dbThread_.join();
            }
        }

    private:
        struct DbLogEntry
        {
            std::string time;
            unsigned tid;
            std::string level;
            std::string message;
        };

        void dbWorker() {
            while (true) {
                DbLogEntry entry;
                {
                    std::unique_lock<std::mutex> lk(queueMutex_);
                    dbCond_.wait(lk, [this] {
                        return dbStop_ || !dbQueue_.empty();
                    });
                    if (dbStop_ && dbQueue_.empty()) break;
                    entry = std::move(dbQueue_.front());
                    dbQueue_.pop();
                }

                // Insert into raw table
                std::string rawTable = tableName_ + "_raw";
                std::ostringstream insertSql;
                insertSql << "INSERT INTO " << rawTable
                    << " (time, tid, level, message) VALUES ('"
                    << entry.time << "', " << entry.tid << ", '"
                    << entry.level << "', '" << entry.message << "');";
                sqlite3_exec(db_, insertSql.str().c_str(), nullptr, nullptr, nullptr);

                // Per-thread table
                std::ostringstream tblName;
                tblName << tableName_ << "_" << entry.tid;
                std::string perThreadTable = tblName.str();

                if (createdTables_.insert(perThreadTable).second) {
                    std::ostringstream createSql;
                    createSql << "CREATE TABLE IF NOT EXISTS " << perThreadTable
                        << " (time TEXT, tid INTEGER, level TEXT, message TEXT);";
                    sqlite3_exec(db_, createSql.str().c_str(), nullptr, nullptr, nullptr);
                }

                std::ostringstream perThreadInsert;
                perThreadInsert << "INSERT INTO " << perThreadTable
                    << " (time, tid, level, message) VALUES ('"
                    << entry.time << "', " << entry.tid << ", '"
                    << entry.level << "', '" << entry.message << "');";
                sqlite3_exec(db_, perThreadInsert.str().c_str(), nullptr, nullptr, nullptr);
            }
        }

        sqlite3* db_;
        std::string tableName_;

        std::queue<DbLogEntry> dbQueue_;
        std::mutex queueMutex_;
        std::condition_variable dbCond_;
        std::thread dbThread_;
        bool dbStop_{false};
        std::set<std::string> createdTables_;
    };


    // Allow chained style: LoggerBuilder().addFileHandler(...), then .addSqliteHandler(...)
    // by adding a method via ADL-like helper:
    struct LoggerBuilderSqliteMixin
    {
        LoggerBuilder& builder;

        LoggerBuilderSqliteMixin(LoggerBuilder& b) : builder(b) {}

        LoggerBuilder& AddSqliteHandler(sqlite3* db, const std::string& tableName) const {
            if (db) builder.addHandler(std::make_unique<SqliteLogHandler>(db, tableName));
            return builder;
        }
    };

    // Convenience function to start a chain that includes sqlite methods if included:
    inline LoggerBuilderSqliteMixin WithSqlite(LoggerBuilder& b) {
        return LoggerBuilderSqliteMixin{b};
    }
} // namespace tenet_tracer


#endif // SQLITE_LOG_HANDLER_H

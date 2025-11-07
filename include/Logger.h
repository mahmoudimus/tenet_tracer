//
// Logger.h
//
// A modular logger with pluggable handlers for different destinations.
// This header is *SQLite-free*. The SQLite handler lives in SqliteLogHandler.{h,cpp}.
//
// Architecture:
//   - LogHandler: abstract interface for log destinations
//   - FileLogHandler: writes to files with rotation and optional per-thread suffixes
//   - Logger: coordinates multiple handlers
//   - LoggerBuilder: fluent API to construct loggers (generic addHandler only)
//
// Example usage (file only):
//   auto logger = tenet_tracer::LoggerBuilder()
//       .addFileHandler("trace.log", 10*1024*1024, true)
//       .setMinLevel(LogLevel::Info)
//       .build();
//
// Example when SQLite extension is compiled and included:
//   #include "SqliteLogHandler.h"
//   auto logger = tenet_tracer::LoggerBuilder()
//       .addFileHandler("trace.log", 10*1024*1024, true)
//       .addHandler<tenet_tracer::SqliteLogHandler>(db, "logs", 100)
//       .setMinLevel(LogLevel::Info)
//       .build();
//

#ifndef LOGGER_H
#define LOGGER_H

#include <cstdarg>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>


namespace tenet_tracer
{
namespace logging
{
    namespace detail {
        inline std::string vformat(const char* fmt, va_list ap) {
            va_list ap_copy;
            va_copy(ap_copy, ap);
            const int needed = std::vsnprintf(nullptr, 0, fmt, ap_copy);
            va_end(ap_copy);
            if (needed <= 0) return {};

            std::string out;
            out.resize(static_cast<size_t>(needed) + 1);
            const int written = std::vsnprintf(&out[0], out.size(), fmt, ap);
            if (written > 0) out.resize(static_cast<size_t>(written));
            else out.clear();
            return out;
        }

        inline std::string format(const char* fmt, ...) {
            va_list ap;
            va_start(ap, fmt);
            std::string s = vformat(fmt, ap);
            va_end(ap);
            return s;
        }
    } // namespace detail

    enum class LogLevel
    {
        Trace = 0,
        Debug = 1,
        Info = 2,
        Warning = 3,
        Error = 4,
        Critical = 5
    };

    inline const char* logLevelToString(LogLevel level)
    {
        switch (level)
        {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARNING";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Critical: return "CRITICAL";
        default: return "UNKNOWN";
        }
    }

    class LogHandler
    {
    public:
        virtual ~LogHandler() = default;
        virtual void log(const std::string& message, unsigned tid, LogLevel level) = 0;
        virtual void setThreadId(unsigned) {}
        virtual void close() {}
    };

    class FileLogHandler : public LogHandler
    {
    public:
        FileLogHandler(const std::string& baseFilename,
            std::size_t maxFileSize = 10 * 1024 * 1024,
            bool appendThreadId = false,
            bool includeLogLevel = true,
            bool includeTimestamp = false)
            : baseFilename_(baseFilename),
            maxFileSize_(maxFileSize),
            appendThreadId_(appendThreadId),
            includeLogLevel_(includeLogLevel),
            includeTimestamp_(includeTimestamp),
            currentThreadId_(static_cast<unsigned>(-1))
        {
        }

        ~FileLogHandler() override { close(); }

        void setThreadId(unsigned tid) override
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (currentThreadId_ != tid)
            {
                currentThreadId_ = tid;
                currentFilename_.clear();
                openFile();
            }
        }

        void log(const std::string& message, unsigned tid, LogLevel level) override
        {
            std::lock_guard<std::mutex> lock(mtx_);

            if (appendThreadId_ && currentThreadId_ != tid)
            {
                currentThreadId_ = tid;
                currentFilename_.clear();
            }

            openFile();
            if (!file_.is_open()) return;

            // Format: [TIMESTAMP] [LEVEL] message
            if (includeTimestamp_) {
                std::time_t now = std::time(nullptr);
                std::tm* tm_info = std::localtime(&now);
                char time_buf[64];
                std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
                file_ << "[" << time_buf << "] ";
            }
            
            if (includeLogLevel_)
                file_ << "[" << logLevelToString(level) << "] " << message << '\n';
            else
                file_ << message << '\n';

            file_.flush();
            rotateIfNeeded();
        }

        void close() override
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (file_.is_open()) file_.close();
        }

    private:
        std::string baseFilename_;
        std::size_t maxFileSize_;
        bool appendThreadId_;
        bool includeLogLevel_;
        bool includeTimestamp_;
        unsigned currentThreadId_;
        std::string currentFilename_;
        std::ofstream file_;
        std::mutex mtx_;

        void openFile()
        {
            std::string filename = baseFilename_;
            if (appendThreadId_ && currentThreadId_ != static_cast<unsigned>(-1))
            {
                std::size_t pos = filename.find_last_of('.');
                if (pos != std::string::npos) filename.insert(pos, "_" + std::to_string(currentThreadId_));
                else filename += "_" + std::to_string(currentThreadId_);
            }

            if (file_.is_open() && currentFilename_ == filename) return;

            if (file_.is_open()) file_.close();

            currentFilename_ = filename;
            file_.open(currentFilename_.c_str(), std::ios::out | std::ios::app);
        }

        void rotateIfNeeded()
        {
            if (maxFileSize_ == 0 || !file_.is_open()) return;

            std::streampos pos = file_.tellp();
            if (pos < 0) return;

            if (static_cast<std::size_t>(pos) >= maxFileSize_)
            {
                file_.close();
                std::string rotated = currentFilename_ + ".old";
                std::remove(rotated.c_str());
                std::rename(currentFilename_.c_str(), rotated.c_str());
                file_.open(currentFilename_.c_str(), std::ios::out | std::ios::trunc);
            }
        }
    };

    class Logger
    {
    public:
        Logger() : currentThreadId_(static_cast<unsigned>(-1)), minLevel_(LogLevel::Trace) {}
        ~Logger() { close(); }

        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;

        Logger(Logger&& other) noexcept
            : handlers_(std::move(other.handlers_)),
            currentThreadId_(other.currentThreadId_),
            minLevel_(other.minLevel_) {
            other.currentThreadId_ = static_cast<unsigned>(-1);
        }

        Logger& operator=(Logger&& other) noexcept
        {
            if (this != &other)
            {
                std::lock_guard<std::mutex> lock(mtx_);
                close();
                handlers_ = std::move(other.handlers_);
                currentThreadId_ = other.currentThreadId_;
                minLevel_ = other.minLevel_;
                other.currentThreadId_ = static_cast<unsigned>(-1);
            }
            return *this;
        }

        void addHandler(std::unique_ptr<LogHandler> handler)
        {
            std::lock_guard<std::mutex> lock(mtx_);
            handlers_.push_back(std::move(handler));
        }

        void setThreadId(unsigned tid)
        {
            std::lock_guard<std::mutex> lock(mtx_);
            currentThreadId_ = tid;
            for (auto& h : handlers_) h->setThreadId(tid);
        }

        void setMinLevel(LogLevel level) { std::lock_guard<std::mutex> lock(mtx_); minLevel_ = level; }
        LogLevel getMinLevel() const { return minLevel_; }

        void log(const std::string& message, LogLevel level = LogLevel::Info)
        {
            if (level < minLevel_) return;
            std::lock_guard<std::mutex> lock(mtx_);
            const unsigned tid = currentThreadId_;
            for (auto& h : handlers_) h->log(message, tid, level);
        }

        // Convenience helpers
        void trace(const std::string& m) { log(m, LogLevel::Trace); }
        void debug(const std::string& m) { log(m, LogLevel::Debug); }
        void info(const std::string& m) { log(m, LogLevel::Info); }
        void warning(const std::string& m) { log(m, LogLevel::Warning); }
        void error(const std::string& m) { log(m, LogLevel::Error); }
        void critical(const std::string& m) { log(m, LogLevel::Critical); }

        void logf(LogLevel level, const char* fmt, ...) {
            if (level < minLevel_) return;
            va_list ap; va_start(ap, fmt);
            std::string msg = detail::vformat(fmt, ap);
            va_end(ap);
            log(msg, level);
        }
        void tracef(const char* fmt, ...) {
            if (LogLevel::Trace < minLevel_) return;
            va_list ap; va_start(ap, fmt); std::string msg = detail::vformat(fmt, ap); va_end(ap);
            log(msg, LogLevel::Trace);
        }
        void debugf(const char* fmt, ...) {
            if (LogLevel::Debug < minLevel_) return;
            va_list ap; va_start(ap, fmt); std::string msg = detail::vformat(fmt, ap); va_end(ap);
            log(msg, LogLevel::Debug);
        }
        void infof(const char* fmt, ...) {
            if (LogLevel::Info < minLevel_) return;
            va_list ap; va_start(ap, fmt); std::string msg = detail::vformat(fmt, ap); va_end(ap);
            log(msg, LogLevel::Info);
        }
        void warningf(const char* fmt, ...) {
            if (LogLevel::Warning < minLevel_) return;
            va_list ap; va_start(ap, fmt); std::string msg = detail::vformat(fmt, ap); va_end(ap);
            log(msg, LogLevel::Warning);
        }
        void errorf(const char* fmt, ...) {
            if (LogLevel::Error < minLevel_) return;
            va_list ap; va_start(ap, fmt); std::string msg = detail::vformat(fmt, ap); va_end(ap);
            log(msg, LogLevel::Error);
        }
        void criticalf(const char* fmt, ...) {
            if (LogLevel::Critical < minLevel_) return;
            va_list ap; va_start(ap, fmt); std::string msg = detail::vformat(fmt, ap); va_end(ap);
            log(msg, LogLevel::Critical);
        }

        void close()
        {
            for (const auto& h : handlers_) h->close();
        }

    private:
        std::vector<std::unique_ptr<LogHandler>> handlers_;
        unsigned currentThreadId_;
        LogLevel minLevel_;
        mutable std::mutex mtx_;
    };

    class LoggerBuilder
    {
    public:
        LoggerBuilder() : minLevel_(LogLevel::Trace) {}

        LoggerBuilder& addFileHandler(const std::string& filename,
            std::size_t maxFileSize = 10 * 1024 * 1024,
            bool appendThreadId = false,
            bool includeLogLevel = true,
            bool includeTimestamp = false)
        {
            handlers_.push_back(std::make_unique<FileLogHandler>(filename, maxFileSize, appendThreadId, includeLogLevel, includeTimestamp));
            return *this;
        }

        // No SQLite here. Use addHandler(...) or include LoggerSqliteExt.h for a fluent helper.
        LoggerBuilder& addHandler(std::unique_ptr<LogHandler> handler)
        {
            handlers_.push_back(std::move(handler));
            return *this;
        }

        // Templated version: construct handler in-place
        // Usage: .addHandler<SqliteLogHandler>(db, "trace", 100)
        template<typename HandlerType, typename... Args>
        LoggerBuilder& addHandler(Args&&... args)
        {
            handlers_.push_back(std::make_unique<HandlerType>(std::forward<Args>(args)...));
            return *this;
        }

        LoggerBuilder& setMinLevel(LogLevel level) { minLevel_ = level; return *this; }

        std::unique_ptr<Logger> build()
        {
            auto logger = std::make_unique<Logger>();
            for (auto& h : handlers_) logger->addHandler(std::move(h));
            logger->setMinLevel(minLevel_);
            handlers_.clear();
            return logger;
        }

    private:
        std::vector<std::unique_ptr<LogHandler>> handlers_;
        LogLevel minLevel_;
    };
    
    namespace winconsole {
        
        extern WINDOWS::HANDLE hStdout;
        
        void _log(WINDOWS::HANDLE hOutput, const char *level, const char *format, va_list args)
        {
            int len;
            char *message;
            char *finalFormat;
            const char *logformat = "\n[%s] %s\n";

            len = snprintf(NULL, 0, logformat, level, format);
            len++; // Trailing null byte.

            finalFormat = (char *)malloc(len);

            len = snprintf(finalFormat, len, logformat, level, format);

            len = vsnprintf(NULL, 0, finalFormat, args);

            message = (char *)malloc(len);

            vsnprintf(message, len, finalFormat, args);

            // Write output
            WINDOWS::WriteConsoleA(hOutput, message, strlen(message), NULL, NULL);

            free(message);
            free(finalFormat);
        }

        void debugLog(const char *fmt, ...)
        {
            // Set console color
            WINDOWS::SetConsoleTextAttribute(hStdout, FOREGROUND_BLUE | FOREGROUND_INTENSITY);

            va_list args;
            va_start(args, fmt);
            _log(hStdout, "DEBUG", fmt, args);

            // Restore console color
            WINDOWS::SetConsoleTextAttribute(hStdout, 15);
        }

        void errorLog(const char *fmt, ...)
        {
            // Set console color
            WINDOWS::SetConsoleTextAttribute(hStdout, 4);

            va_list args;
            va_start(args, fmt);
            _log(hStdout, "ERROR", fmt, args);

            // Restore console color
            WINDOWS::SetConsoleTextAttribute(hStdout, 15);
        }

        void highlightedLog(const char *fmt, ...)
        {
            // Set console color
            WINDOWS::SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            va_list args;
            va_start(args, fmt);
            _log(hStdout, "DETECTION", fmt, args);

            // Restore console color
            WINDOWS::SetConsoleTextAttribute(hStdout, 15);
        }

        void verboseLog(const char *title, const char *fmt, ...)
        {
            // Set console color
            WINDOWS::SetConsoleTextAttribute(hStdout, 14);

            va_list args;
            va_start(args, fmt);
            _log(hStdout, title, fmt, args);

            // Restore console color
            WINDOWS::SetConsoleTextAttribute(hStdout, 15);
        }
    }
} // namespace logging
} // namespace tenet_tracer

#endif // LOGGER_H
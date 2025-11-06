#pragma once
#include "pin.H"

// Policies for generic RW lock wrapper
struct PinRwMutexPolicy {
    typedef PIN_RWMUTEX Handle;
    static void init(Handle* h) { PIN_RWMutexInit(h); }
    static void fini(Handle* h) { PIN_RWMutexFini(h); }
    static void readLock(Handle* h) { PIN_RWMutexReadLock(h); }
    static void writeLock(Handle* h) { PIN_RWMutexWriteLock(h); }
    static void unlock(Handle* h) { PIN_RWMutexUnlock(h); }
};

struct PinClientLockPolicy {
    struct Handle { }; // no actual state
    static void init(Handle*) { }
    static void fini(Handle*) { }
    static void readLock(Handle*) { PIN_LockClient(); }
    static void writeLock(Handle*) { PIN_LockClient(); }
    static void unlock(Handle*) { PIN_UnlockClient(); }
};

// Generic owning RW lock with RAII guards; Policy supplies the PIN calls
template <typename Policy>
class PinRWLock {
public:
    PinRWLock() { Policy::init(&handle_); }
    ~PinRWLock() { Policy::fini(&handle_); }

    class ReadGuard {
    public:
        explicit ReadGuard(PinRWLock& m) : m_(&m), owns_(true) { Policy::readLock(&m_->handle_); }
        ~ReadGuard() { if (owns_ && m_) Policy::unlock(&m_->handle_); }
        ReadGuard(const ReadGuard&) = delete;
        ReadGuard& operator=(const ReadGuard&) = delete;
        ReadGuard(ReadGuard&& other) noexcept : m_(other.m_), owns_(other.owns_) { other.m_ = nullptr; other.owns_ = false; }
    private:
        PinRWLock* m_;
        bool owns_;
    };
    class WriteGuard {
    public:
        explicit WriteGuard(PinRWLock& m) : m_(&m), owns_(true) { Policy::writeLock(&m_->handle_); }
        ~WriteGuard() { if (owns_ && m_) Policy::unlock(&m_->handle_); }
        WriteGuard(const WriteGuard&) = delete;
        WriteGuard& operator=(const WriteGuard&) = delete;
        WriteGuard(WriteGuard&& other) noexcept : m_(other.m_), owns_(other.owns_) { other.m_ = nullptr; other.owns_ = false; }
    private:
        PinRWLock* m_;
        bool owns_;
    };

    ReadGuard acquire_read() { return ReadGuard(*this); }
    WriteGuard acquire_write() { return WriteGuard(*this); }

    PinRWLock(const PinRWLock&) = delete;
    PinRWLock& operator=(const PinRWLock&) = delete;
private:
    typename Policy::Handle handle_;
};

// Convenient aliases
using PinRwMutex = PinRWLock<PinRwMutexPolicy>;
using PinClientMutex = PinRWLock<PinClientLockPolicy>;

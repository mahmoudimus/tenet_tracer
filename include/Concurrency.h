#pragma once
#include "pin.H"
#include <cassert>

namespace tenet_tracer {
namespace concurrency {

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

// Policy for PIN_LOCK (simple exclusive lock)
struct PinSpinLockPolicy {
    typedef PIN_LOCK Handle;
    static void init(Handle* h) { PIN_InitLock(h); }
    static void fini(Handle*) { }
    static void readLock(Handle* h) { PIN_GetLock(h, 0); }
    static void writeLock(Handle* h) { PIN_GetLock(h, 0); }
    static void unlock(Handle* h) { PIN_ReleaseLock(h); }
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
using PinSpinLock = PinRWLock<PinSpinLockPolicy>;

// RAII wrapper for PIN_SEMAPHORE
class PinSemaphore {
public:
    PinSemaphore() { PIN_SemaphoreInit(&sem_); }
    ~PinSemaphore() { PIN_SemaphoreFini(&sem_); }

    void set() { PIN_SemaphoreSet(&sem_); }
    void clear() { PIN_SemaphoreClear(&sem_); }
    void wait() { PIN_SemaphoreWait(&sem_); }
    bool wait_timed(uint32_t milliseconds) { 
        return PIN_SemaphoreTimedWait(&sem_, milliseconds); 
    }
    bool is_set() { return PIN_SemaphoreIsSet(&sem_); }

    PinSemaphore(const PinSemaphore&) = delete;
    PinSemaphore& operator=(const PinSemaphore&) = delete;

private:
    PIN_SEMAPHORE sem_;
};

// Thread abstraction using Pin's internal threads
class Runnable {
public:
    virtual ~Runnable() { }
    virtual void run() = 0;
    static void threadFunc(void *vpRunnable) {
        Runnable *runnable = static_cast<Runnable*>(vpRunnable);
        runnable->run();
    }
};

class Thread {
public:
    typedef void (*ThreadFunc)(void*);
    
    virtual ~Thread() { }
    
    virtual void run() = 0;
    
    PIN_THREAD_UID uid() const { return uid_; }
    
    void wait(INT32 timeout_ms = PIN_INFINITE_TIMEOUT) {
        INT32 exitCode;
        PIN_WaitForThreadTermination(uid_, timeout_ms, &exitCode);
    }

protected:
    Thread() : uid_(0) { }
    PIN_THREAD_UID uid_;
};

// Base class for type-erased lambda wrapper cleanup
struct LambdaWrapperBase {
    virtual ~LambdaWrapperBase() { }
    virtual void invoke() = 0;
    static void invoke_static(void* p) {
        LambdaWrapperBase* wrapper = static_cast<LambdaWrapperBase*>(p);
        wrapper->invoke();
        delete wrapper;
    }
};

// Helper to wrap lambdas/callables for Pin thread creation
template<typename Callable>
struct LambdaWrapper : public LambdaWrapperBase {
    Callable callable;
    LambdaWrapper(Callable&& c) : callable(std::move(c)) { }
    void invoke() override {
        callable();
    }
};

class PinThread : public Thread {
public:
    // Default stack size (64MB)
    static const int DEFAULT_STACK_SIZE = 64 * 1024 * 1024;
    
    PinThread(ThreadFunc func, void *param, int stackSize = DEFAULT_STACK_SIZE) 
        : m_thread_p(INVALID_THREADID)
        , m_func(func)
        , m_param(param)
        , m_has_lambda_wrapper(false)
        , m_stack_size(stackSize)
    {
    }
    
    // Template constructor for lambdas and any callable
    template<typename Callable>
    PinThread(Callable&& callable, int stackSize = DEFAULT_STACK_SIZE)
        : m_thread_p(INVALID_THREADID)
        , m_func(LambdaWrapperBase::invoke_static)
        , m_param(new LambdaWrapper<Callable>(std::forward<Callable>(callable)))
        , m_has_lambda_wrapper(true)
        , m_stack_size(stackSize)
    {
    }
    
    ~PinThread() {
        // If thread wasn't started and we have a lambda wrapper, clean it up
        if (m_has_lambda_wrapper && m_thread_p == INVALID_THREADID && m_param) {
            delete static_cast<LambdaWrapperBase*>(m_param);
        }
    }
    
    void run() {
        m_thread_p = PIN_SpawnInternalThread(m_func, m_param, m_stack_size, &uid_);
        assert(m_thread_p != INVALID_THREADID);
    }
    
    THREADID thread_id() const { return m_thread_p; }

private:
    THREADID m_thread_p;
    Thread::ThreadFunc m_func;
    void *m_param;
    bool m_has_lambda_wrapper;
    int m_stack_size;
};

} // namespace concurrency
} // namespace tenet_tracer

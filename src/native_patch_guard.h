#pragma once
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <sys/syscall.h>

namespace bridge {
    class NativePatchGuard {
        public:
            using MutexFn = int (*)(pthread_mutex_t *);
            
        private:
            pthread_mutex_t *mutex_;
            MutexFn trylock_, unlock_;
            bool held_ = false;
            const char *failure_ = "none";
            int error_ = 0;
            static long Raw(long number, long a = 0, long b = 0, long c = 0) {
                long result;
                __asm__ volatile("int $0x80"
                         : "=a"(result)
                         : "0"(number), "b"(a), "c"(b), "d"(c)
                         : "memory", "cc");
                return result;
            }
            bool Fail(const char *reason, int error) {
                failure_ = reason;
                error_ = error;
                return false;
            }
            static bool Clock(uint64_t &out) {
                struct timespec now{};
                static_assert(sizeof(now) == 8, "Requires i386 time32 syscall layout");
                if (Raw(SYS_clock_gettime, CLOCK_MONOTONIC, reinterpret_cast<long>(&now)) < 0)
                    return false;
                out = uint64_t(now.tv_sec) * 1000u + uint32_t(now.tv_nsec) / 1000000u;
                return true;
            }
            
        public:
            explicit NativePatchGuard(void *mutex, MutexFn trylock, MutexFn unlock)
            : mutex_(static_cast<pthread_mutex_t *>(mutex)), trylock_(trylock), unlock_(unlock) {}
            NativePatchGuard(const NativePatchGuard &) = delete;
            NativePatchGuard &operator=(const NativePatchGuard &) = delete;
            ~NativePatchGuard() { Release(); }
            bool Sync() {
                const long result = Raw(SYS_membarrier, 1 << 5); // PRIVATE_EXPEDITED_SYNC_CORE
                return result >= 0 || Fail("membarrier SYNC_CORE failed", int(-result));
            }
            bool Acquire(unsigned timeout_ms = 500) {
                const long supported = Raw(SYS_membarrier, 0);
                if (supported < 0)
                    return Fail("membarrier query failed", int(-supported));
                if ((supported & ((1 << 5) | (1 << 6))) != ((1 << 5) | (1 << 6)))
                    return Fail("kernel lacks membarrier SYNC_CORE", ENOSYS);
                const long registered = Raw(SYS_membarrier, 1 << 6);
                if (registered < 0)
                    return Fail("membarrier registration failed", int(-registered));
                if (!Sync())
                    return false;
                uint64_t started = 0;
                if (!Clock(started))
                    return Fail("monotonic clock failed", EIO);
                for (;;) {
                    const int result = trylock_(mutex_);
                    if (!result) {
                        held_ = true;
                        return true;
                    }
                    if (result == EOWNERDEAD) {
                        unlock_(mutex_);
                        return Fail("native mutex owner died", result);
                    }
                    if (result != EBUSY)
                        return Fail("native mutex trylock failed", result);
                    uint64_t now = 0;
                    if (!Clock(now) || now - started >= timeout_ms)
                        return Fail("native mutex acquisition timed out", ETIMEDOUT);
                    const struct timespec delay{0, 1000000};
                    Raw(SYS_nanosleep, reinterpret_cast<long>(&delay));
                }
            }
            void Release() {
                if (held_) {
                    unlock_(mutex_);
                    held_ = false;
                }
            }
            const char *Failure() const { return failure_; }
            int Error() const { return error_; }
    };
}
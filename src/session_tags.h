#pragma once
#include <stdint.h>

namespace bridge {
    class SessionTags {
        struct Entry {
            uint64_t peer = 0;
            bool archive = false;
        };
        Entry entries_[512]{};
        uint32_t lock_ = 0;
        void Lock() {
            while (__atomic_exchange_n(&lock_, 1u, __ATOMIC_ACQUIRE))
                __asm__ volatile("pause" ::: "memory");
        }
        void Unlock() { __atomic_store_n(&lock_, 0u, __ATOMIC_RELEASE); }
        
        public:
            bool Set(uint64_t peer, bool archive) {
                if (!peer)
                    return false;
                Lock();
                Entry *vacant = nullptr;
                for (auto &entry : entries_) {
                    if (entry.peer == peer) {
                        entry.archive = archive;
                        Unlock();
                        return true;
                    }
                    if (!entry.peer && !vacant)
                        vacant = &entry;
                }
                if (vacant)
                    *vacant = {peer, archive};
                Unlock();
                return vacant != nullptr;
            }
            bool IsArchive(uint64_t peer) {
                Lock();
                bool archive = false;
                for (const auto &entry : entries_)
                if (entry.peer == peer && peer) {
                    archive = entry.archive;
                    break;
                }
                Unlock();
                return archive;
            }
            void Remove(uint64_t peer) {
                Lock();
                for (auto &entry : entries_)
                if (entry.peer == peer) {
                    entry = {};
                    break;
                }
                Unlock();
            }
    };
}
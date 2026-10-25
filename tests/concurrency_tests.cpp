#ifdef NDEBUG
#undef NDEBUG
#endif
#include "../src/auth_route.h"
#include "../src/route_frames.h"
#include "../src/lifecycle.h"
#include "../src/session_tags.h"
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

#if defined(__linux__) && defined(__i386__)
#include "../src/native_patch_guard.h"
#include <signal.h>
#include <pthread.h>
#endif

namespace {
class Barrier {
    std::mutex mutex_;
    std::condition_variable changed_;
    unsigned count_ = 0, epoch_ = 0, total_;
public:
    explicit Barrier(unsigned total) : total_(total) {}
    void Wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        const unsigned epoch = epoch_;
        if (++count_ == total_) { count_ = 0; ++epoch_; changed_.notify_all(); }
        else changed_.wait(lock, [&] { return epoch_ != epoch; });
    }
};
struct Entry { uint64_t peer, game; };
struct Server { std::mutex native_mutex; std::vector<Entry> entries; };
struct Ticket { uint64_t peer, app; };

bool Exists(void *context, uint64_t peer, uint64_t game) {
    for (const auto &entry : static_cast<Server *>(context)->entries)
        if (entry.peer == peer && entry.game == game) return true;
    return false;
}
int Verify(void *, const uint64_t *game, const void *data, int, int *offset,
           uint64_t *identity, uint64_t) {
    const auto &ticket = *static_cast<const Ticket *>(data);
    *offset = 8;
    *identity = ticket.peer;
    return *game == ticket.app ? bridge::kOK : bridge::kWrongGame;
}
int Register(void *context, int, const uint64_t *game, const void *, int, int,
             uint64_t peer, uint32_t *, void *) {
    auto &server = *static_cast<Server *>(context);
    if (Exists(context, peer, *game)) return bridge::kDuplicate;
    server.entries.push_back({peer, *game});
    return bridge::kOK;
}
void End(void *context, uint64_t peer, const uint64_t *game) {
    auto &entries = static_cast<Server *>(context)->entries;
    for (auto it = entries.begin(); it != entries.end();) {
        if (it->peer == peer && it->game == *game) it = entries.erase(it);
        else ++it;
    }
}
const bridge::Api api{Verify, Register, End, nullptr, nullptr, Exists};

void AuthRace() {
    constexpr unsigned workers = 16, rounds = 1500;
    Barrier barrier(workers);
    Server server;
    std::atomic<unsigned> accepted{0}, duplicates{0};
    std::vector<std::thread> threads;
    for (unsigned worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            bridge::RouteFrames frames;
            for (unsigned round = 0; round < rounds; ++round) {
                if (worker == 0) { accepted = 0; duplicates = 0; }
                barrier.Wait();
                const uint64_t peer = UINT64_C(76561198012345678) + round;
                Ticket ticket{peer, (worker + round) % 2 ? bridge::kServerApp : bridge::kArchiveApp};
                const uint64_t base = bridge::kServerApp;
                int result;
                // Mirrors the native critical section, independently verified
                // against the pinned CGameServer::BeginAuthSession binary.
                {
                    std::lock_guard<std::mutex> lock(server.native_mutex);
                    auto *selection = frames.Begin(0x2000);
                    assert(selection);
                    int offset = 0;
                    uint64_t identity = 0;
                    result = bridge::Verify(api, *selection, &server, &base, &ticket,
                                            sizeof(ticket), &offset, &identity, peer);
                    assert(result == 0 && identity == peer);
                    bridge::Selection chosen{};
                    assert(frames.Take(0x2000, chosen));
                    result = bridge::Register(api, chosen, &server, 1, &base, &ticket,
                                              sizeof(ticket), offset, peer, nullptr, nullptr);
                }
                if (result == 0) ++accepted;
                else { assert(result == 2); ++duplicates; }
                barrier.Wait();
                if (worker == 0) {
                    assert(accepted == 1 && duplicates == workers - 1);
                    std::lock_guard<std::mutex> lock(server.native_mutex);
                    assert(server.entries.size() == 1);
                    bridge::End(api, &server, peer, &base);
                    assert(server.entries.empty());
                }
                barrier.Wait();
            }
        });
    }
    for (auto &thread : threads) thread.join();
    std::printf("PASS: %u real threads, %u simultaneous auth attempts, exactly one winner per account\n",
                workers, workers * rounds);
}

void LifecycleRaces() {
    bridge::Lifecycle lifecycle;
    std::atomic<unsigned> winners{0};
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 32; ++i) threads.emplace_back([&] {
        if (lifecycle.Move(bridge::Phase::Cold, bridge::Phase::Installing)) ++winners;
    });
    for (auto &thread : threads) thread.join();
    assert(winners == 1 && lifecycle.Get() == bridge::Phase::Installing);
    assert(!lifecycle.StopBeforeInstall());
    lifecycle.Finish(bridge::Phase::Active);
    threads.clear();
    for (unsigned i = 0; i < 32; ++i) threads.emplace_back([&] {
        assert(!lifecycle.StopBeforeInstall());
        assert(lifecycle.Get() == bridge::Phase::Active);
    });
    for (auto &thread : threads) thread.join();
    for (unsigned round = 0; round < 500; ++round) {
        bridge::Lifecycle waiting;
        waiting.Finish(bridge::Phase::Waiting);
        Barrier start(2);
        bool installer = false, cancelled = false;
        std::thread one([&] { start.Wait(); installer = waiting.Move(bridge::Phase::Waiting, bridge::Phase::Installing); });
        std::thread two([&] { start.Wait(); cancelled = waiting.StopBeforeInstall(); });
        one.join(); two.join();
        assert(installer != cancelled);
        assert(waiting.Get() == (installer ? bridge::Phase::Installing : bridge::Phase::Stopped));
    }
    std::puts("PASS: concurrent initialization/cancellation/unload lifecycle races");
}

void NestedRoutes() {
    bridge::RouteFrames frames;
    auto *outer = frames.Begin(0x2000);
    assert(outer); outer->archive = true; outer->peer = 123;
    auto *inner = frames.Begin(0x1000);
    assert(inner); inner->peer = 456;
    bridge::Selection chosen{};
    assert(frames.Take(0x1000, chosen) && chosen.peer == 456 && !chosen.archive);
    assert(frames.Take(0x2000, chosen) && chosen.peer == 123 && chosen.archive);
    assert(!frames.Take(0x2000, chosen));
    for (unsigned i = 0; i < 16; ++i) assert(frames.Begin(0x2000 - i * 16));
    assert(!frames.Begin(0x1000));
    assert(frames.Begin(0x3000)); // Stale deeper frames are discarded.
    std::puts("PASS: nested routes, consumed frame rejection and bounded nesting");
}

void RouteLabelsRace() {
    bridge::SessionTags tags;
    std::vector<std::thread> threads;
    for (unsigned worker = 0; worker < 16; ++worker) threads.emplace_back([&, worker] {
        const uint64_t peer = UINT64_C(76561198012345678) + worker;
        for (unsigned round = 0; round < 1000; ++round) {
            const bool archive = (round & 1) != 0;
            assert(tags.Set(peer, archive));
            assert(tags.IsArchive(peer) == archive);
            tags.Remove(peer);
            assert(!tags.IsArchive(peer));
        }
    });
    for (auto &thread : threads) thread.join();
    std::puts("PASS: 16 real threads concurrently update/read/remove independent console route labels");
}

#if defined(__linux__) && defined(__i386__)
void KernelQuiescence() {
    pthread_mutex_t mutex;
    assert(pthread_mutex_init(&mutex, nullptr) == 0);
    std::atomic<bool> run{true};
    std::atomic<unsigned> ready{0};
    std::atomic<uint32_t> counter{0};
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 16; ++i) workers.emplace_back([&] {
        sigset_t mask;
        sigfillset(&mask);
        assert(pthread_sigmask(SIG_BLOCK, &mask, nullptr) == 0);
        ++ready;
        while (run.load(std::memory_order_relaxed)) {
            assert(pthread_mutex_lock(&mutex) == 0);
            ++counter;
            assert(pthread_mutex_unlock(&mutex) == 0);
            std::this_thread::yield();
        }
    });
    while (ready != 16) std::this_thread::yield();
    for (unsigned round = 0; round < 100; ++round) {
        bridge::NativePatchGuard guarded(&mutex);
        assert(guarded.Acquire());
        const uint32_t before = counter.load();
        for (unsigned i = 0; i < 10000; ++i) assert(counter.load() == before);
        assert(guarded.Sync());
        guarded.Release();
    }
    run = false;
    for (auto &worker : workers) worker.join();
    assert(pthread_mutex_lock(&mutex) == 0);
    bridge::NativePatchGuard refused(&mutex);
    assert(!refused.Acquire(20) && refused.Error() == ETIMEDOUT);
    assert(pthread_mutex_unlock(&mutex) == 0);
    assert(pthread_mutex_destroy(&mutex) == 0);
    std::puts("PASS: real Linux native mutex, SYNC_CORE, 16 signal-blocking workers and bounded lock timeout");
}
#endif
} // namespace

int main() {
    NestedRoutes();
    RouteLabelsRace();
    AuthRace();
    LifecycleRaces();
#if defined(__linux__) && defined(__i386__)
    KernelQuiescence();
#else
    std::puts("NOT RUN on this host: Linux kernel native-mutex/membarrier test");
#endif
}

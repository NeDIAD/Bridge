#include "../src/auth_route.h"
#include "../src/native_sessions.h"
using namespace bridge;
extern "C" void *memcpy(void *dst, const void *src, size_t n) {
    auto *d = static_cast<unsigned char *>(dst);
    auto *s = static_cast<const unsigned char *>(src);
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}

namespace {
int first_result, archive_result, register_result, verify_calls, register_calls;
int end_calls, license_calls, license_result;
uint64_t seen_game, seen_peer, emitted_identity;
uint64_t ended_games[2];
uint32_t seen_app;
const uint64_t peer = UINT64_C(76561198012345678);
const uint64_t base = kServerApp;
char ticket[100];
alignas(4) char server_bytes[0x1800];
void *server = server_bytes;
NativeAuthEntry entries[8];
bool track_sessions;
int entry_count;
void Sync() {
    const NativeAuthEntry *ptr = entries;
    __builtin_memcpy(server_bytes + 0x1700, &ptr, sizeof(ptr));
    __builtin_memcpy(server_bytes + 0x170c, &entry_count, sizeof(entry_count));
}
bool FakeExists(void *self, uint64_t remote, uint64_t game) {
    return NativeSessionExists(self, remote, game);
}

int FakeVerify(void *, const uint64_t *game, const void *, int,
               int *offset, uint64_t *identity, uint64_t) {
    ++verify_calls;
    *offset = 40;
    *identity = emitted_identity;
    return *game == kArchiveApp ? archive_result : first_result;
}
int FakeRegister(void *, int, const uint64_t *game, const void *, int,
                 int, uint64_t remote, uint32_t *, void *) {
    ++register_calls;
    seen_game = *game;
    seen_peer = remote;
    if (track_sessions && register_result == kOK) {
        if (NativeSessionExists(server, remote, *game)) return kDuplicate;
        entries[entry_count].mode = 1;
        entries[entry_count].peer = remote;
        entries[entry_count].game = *game;
        ++entry_count;
        Sync();
    }
    return register_result;
}
void FakeEnd(void *, uint64_t remote, const uint64_t *game) {
    if (end_calls < 2) ended_games[end_calls] = *game;
    ++end_calls;
    seen_peer = remote;
    if (track_sessions) {
        for (int i = entry_count - 1; i >= 0; --i) {
            if (entries[i].peer == remote && entries[i].game == *game) {
                entries[i] = entries[--entry_count];
            }
        }
        Sync();
    }
}
int FakeLicense(void *, uint64_t remote, const uint64_t *game, uint32_t app) {
    ++license_calls;
    seen_game = *game;
    seen_peer = remote;
    seen_app = app;
    return *game == kArchiveApp ? 1 : license_result;
}
Api api{FakeVerify, FakeRegister, FakeEnd, FakeLicense, nullptr, FakeExists};
void Reset() {
    first_result = kOK;
    archive_result = kOK;
    register_result = kOK;
    emitted_identity = peer;
    verify_calls = register_calls = end_calls = license_calls = 0;
    seen_game = seen_peer = seen_app = 0;
    license_result = kNoAuth;
    track_sessions = false;
    entry_count = 0;
    Sync();
}
int Start(Selection &s, const uint64_t &game = base, uint64_t remote = peer,
          VerifyTrace *trace = nullptr) {
    int offset = -1;
    uint64_t identity = 0;
    return Verify(api, s, server, &game, ticket, sizeof(ticket), &offset, &identity, remote, trace);
}
int Finish(Selection &s, uint64_t remote = peer, int offset = 40) {
    uint32_t handle = 0;
    return Register(api, s, server, 1, &base, ticket, sizeof(ticket), offset,
                    remote, &handle, nullptr);
}
}

#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)
extern "C" int test_main() {
    Selection s{};
    VerifyTrace trace{};
    Reset();
    CHECK(Start(s, base, peer, &trace) == kOK);
    CHECK(trace.expected_game == kServerApp && trace.original_result == kOK && trace.archive_result == -1);
    first_result = kWrongGame;
    CHECK(Start(s, base, peer, &trace) == kOK);
    CHECK(trace.original_result == kWrongGame && trace.archive_result == kOK);
    archive_result = kWrongGame;
    CHECK(Start(s, base, peer, &trace) == kWrongGame);
    CHECK(trace.original_result == kWrongGame && trace.archive_result == kWrongGame && !s.archive);
    const uint64_t other_app = 440;
    CHECK(Start(s, other_app, peer, &trace) == kWrongGame);
    CHECK(trace.expected_game == other_app && trace.archive_result == -1);
    Reset();
    CHECK(Start(s) == kOK && verify_calls == 1 && !s.archive);
    CHECK(Finish(s) == kOK && seen_game == kServerApp && seen_peer == peer);

    const int non_app_errors[] = {1, 2, 3, 5};
    for (int failure : non_app_errors) {
        Reset();
        first_result = failure;
        CHECK(Start(s) == failure && verify_calls == 1 && !s.archive);
    }
    Reset();
    first_result = kWrongGame;
    CHECK(Start(s) == kOK && verify_calls == 2 && s.archive);
    CHECK(Finish(s) == kOK && seen_game == kArchiveApp && seen_peer == peer);
    CHECK(!s.archive);

    const int archive_errors[] = {1, 2, 3, 4, 5};
    for (int failure : archive_errors) {
        Reset();
        first_result = kWrongGame;
        archive_result = failure;
        CHECK(Start(s) == failure && !s.archive);
    }
    Reset();
    first_result = kWrongGame;
    const uint64_t unrelated = 440;
    CHECK(Start(s, unrelated) == kWrongGame && verify_calls == 1);

    Reset();
    first_result = kWrongGame;
    emitted_identity = peer + 1;
    CHECK(Start(s) == kOK && !s.archive); // Native caller rejects the mismatch.

    Reset();
    first_result = kWrongGame;
    CHECK(Start(s) == kOK && s.archive);
    CHECK(Finish(s, peer + 1) == kInvalid && register_calls == 0 && !s.archive);
    CHECK(Start(s) == kOK && s.archive);
    CHECK(Finish(s, peer, 41) == kInvalid && register_calls == 0 && !s.archive);

    Reset();
    first_result = kWrongGame;
    CHECK(Start(s) == kOK && s.archive);
    first_result = kInvalid;
    CHECK(Start(s) == kInvalid && !s.archive); // Clear stale selection.

    Reset();
    first_result = kWrongGame;
    CHECK(Start(s) == kOK && s.archive);
    register_result = 2;
    CHECK(Finish(s) == 2 && !s.archive); // Duplicate session remains an error.

    Reset();
    Selection other_thread{};
    first_result = kWrongGame;
    CHECK(Start(s) == kOK && s.archive);
    first_result = kOK;
    CHECK(Start(other_thread) == kOK && !other_thread.archive && s.archive);
    CHECK(Finish(other_thread) == kOK && seen_game == kServerApp);
    CHECK(Finish(s) == kOK && seen_game == kArchiveApp);

    Reset();
    End(api, server, peer, &base);
    CHECK(end_calls == 2 && ended_games[0] == kServerApp && ended_games[1] == kArchiveApp);
    Reset();
    End(api, server, peer, &unrelated);
    CHECK(end_calls == 1 && ended_games[0] == unrelated);

    Reset();
    CHECK(License(api, server, peer, &base, 999) == 1);
    CHECK(license_calls == 2 && seen_game == kArchiveApp && seen_app == 999 && seen_peer == peer);
    Reset();
    license_result = 1;
    CHECK(License(api, server, peer, &base, 999) == 1 && license_calls == 1);
    Reset();
    license_result = 0;
    CHECK(License(api, server, peer, &base, 999) == 0 && license_calls == 1);
    // Real requirement: SAME SteamID switches AppId in either direction.
    const int first_apps[] = {730, 4465480};
    for (int app : first_apps) {
        Reset();
        track_sessions = true;
        first_result = app == 730 ? kOK : kWrongGame;
        CHECK(Start(s) == kOK && Finish(s) == kOK && entry_count == 1);
        // Pending native session already blocks the opposite AppId.
        first_result = app == 730 ? kWrongGame : kOK;
        CHECK(Start(s) == kOK);
        CHECK(Finish(s) == kDuplicate && entry_count == 1 && register_calls == 1);
        // The native state 3 also counts as active.
        entries[0].mode = 3;
        CHECK(Start(s) == kOK && Finish(s) == kDuplicate && register_calls == 1);
        End(api, server, peer, &base);
        CHECK(entry_count == 0);
        CHECK(Start(s) == kOK && Finish(s) == kOK && entry_count == 1);
        // Same-AppId duplicates remain the original registrar's result.
        CHECK(Start(s) == kOK && Finish(s) == kDuplicate && entry_count == 1);
    }
    Reset();
    track_sessions = true;
    first_result = kWrongGame;
    CHECK(Start(s) == kOK && Finish(s) == kOK);
    first_result = kOK;
    emitted_identity = peer + 1;
    CHECK(Start(s, base, peer + 1) == kOK);
    CHECK(Finish(s, peer + 1) == kOK && entry_count == 2);
    // Different SteamIDs do not collide. Unrelated apps and send states do not
    // become incoming-session duplicates.
    CHECK(!NativeSessionExists(server, peer + 2, kArchiveApp));
    entries[0].mode = 0;
    CHECK(!NativeSessionExists(server, peer, kArchiveApp));
    entries[0].mode = 2;
    CHECK(!NativeSessionExists(server, peer, kArchiveApp));
    entries[0].mode = 1;
    entries[0].game = 440;
    CHECK(!NativeSessionExists(server, peer, kArchiveApp));
    return 0;
}

extern "C" __attribute__((naked)) void _start() {
    __asm__ volatile("andl $-16, %esp\ncalll test_main\nmovl %eax, %ebx\nmovl $1, %eax\nint $0x80");
}


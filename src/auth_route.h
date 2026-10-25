#pragma once
#include <stdint.h>

namespace bridge {
constexpr uint64_t kServerApp = 730;
constexpr uint64_t kArchiveApp = 4465480;
constexpr int kOK = 0;
constexpr int kInvalid = 1;
constexpr int kDuplicate = 2; // k_EBeginAuthSessionResultDuplicateRequest
constexpr int kWrongGame = 4;

using VerifyFn = int (*)(void *, const uint64_t *, const void *, int, int *, uint64_t *, uint64_t);
using RegisterFn = int (*)(void *, int, const uint64_t *, const void *, int, int, uint64_t,
                           uint32_t *, void *);
using EndFn = void (*)(void *, uint64_t, const uint64_t *);
using SessionExistsFn = bool (*)(void *, uint64_t, uint64_t);

struct Api {
    VerifyFn verify;
    RegisterFn register_session;
    EndFn end_session;
    SessionExistsFn session_exists;
};

struct Selection {
    void *server;
    const void *ticket;
    int length;
    int offset;
    uint64_t peer;
    bool archive;
};

struct VerifyTrace {
    uint64_t expected_game;
    int original_result;
    int archive_result;
};

inline int Verify(const Api &api, Selection &selection, void *server, const uint64_t *game,
                  const void *ticket, int length, int *offset, uint64_t *identity, uint64_t peer,
                  VerifyTrace &trace) {
    selection = {};
    trace = {game ? *game : 0, -1, -1};
    int result = api.verify(server, game, ticket, length, offset, identity, peer);
    trace.original_result = result;
    if (result != kWrongGame || !game || *game != kServerApp)
        return result;

    const uint64_t archive = kArchiveApp;
    result = api.verify(server, &archive, ticket, length, offset, identity, peer);
    trace.archive_result = result;
    
    if (result == kOK && identity && offset && *identity == peer && *offset >= 0 &&
        *offset < length) {
        selection = {server, ticket, length, *offset, peer, true};
    }
    return result;
}

inline int Register(const Api &api, Selection &selection, void *server, int mode,
                    const uint64_t *game, const void *ticket, int length, int offset, uint64_t peer,
                    uint32_t *handle, void *extra, bool &routed) {
    const Selection chosen = selection;
    selection = {};
    routed = false;
    uint64_t selected_game = game ? *game : 0;
    if (chosen.archive) {
        if (chosen.server != server || chosen.ticket != ticket || chosen.length != length ||
            chosen.offset != offset || chosen.peer != peer || mode != 1 || !game ||
            *game != kServerApp)
            return kInvalid;
        selected_game = kArchiveApp;
    }

    if (mode == 1 && (selected_game == kServerApp || selected_game == kArchiveApp)) {
        const uint64_t other = selected_game == kServerApp ? kArchiveApp : kServerApp;
        if (!api.session_exists)
            return kInvalid;
        if (api.session_exists(server, peer, other))
            return kDuplicate;
    }
    const int result = api.register_session(server, mode, chosen.archive ? &selected_game : game,
                                            ticket, length, offset, peer, handle, extra);
    routed = chosen.archive && result == kOK;
    return result;
}

inline void End(const Api &api, void *server, uint64_t peer, const uint64_t *game) {
    api.end_session(server, peer, game);
    if (game && *game == kServerApp) {
        const uint64_t archive = kArchiveApp;
        api.end_session(server, peer, &archive);
    }
}

}

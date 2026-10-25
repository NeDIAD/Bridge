#pragma once
#include <stdint.h>
#include <stddef.h>

namespace bridge {
    struct NativeAuthEntry {
        uint32_t mode;
        uint32_t response;
        uint64_t peer;
        uint64_t game;
        unsigned char remaining[0x8c - 24];
    };
    static_assert(sizeof(NativeAuthEntry) == 0x8c, "Steamclient auth entry ABI");
    static_assert(offsetof(NativeAuthEntry, peer) == 8, "SteamID offset");
    static_assert(offsetof(NativeAuthEntry, game) == 0x10, "CGameID offset");
    
    inline bool NativeSessionExists(void *server, uint64_t peer, uint64_t game) {
        const NativeAuthEntry *entries = nullptr;
        int count = 0;
        __builtin_memcpy(&entries, static_cast<const char *>(server) + 0x1700, sizeof(entries));
        __builtin_memcpy(&count, static_cast<const char *>(server) + 0x170c, sizeof(count));
        for (int i = 0; i < count; ++i) {
            const auto &entry = entries[i];
            if ((entry.mode & ~2u) == 1 && entry.peer == peer && entry.game == game)
                return true;
        }
        return false;
    }
}

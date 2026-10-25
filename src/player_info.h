#pragma once
#include <stdint.h>
#include <stddef.h>

namespace bridge {
    struct alignas(8) PlayerInfo {
        uint64_t version;
        uint64_t xuid;
        char name[128];
        unsigned char remaining_sdk_fields[368];
    };
    static_assert(sizeof(PlayerInfo) == 512, "Player-info output buffer capacity");
    static_assert(offsetof(PlayerInfo, xuid) == 8 && offsetof(PlayerInfo, name) == 16,
                "CS:GO player identity fields");
    constexpr int kAbsolutePlayerLimit = 255; // hl2sdk/csgo/public/const.h
}

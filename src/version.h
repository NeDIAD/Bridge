#pragma once
#define BRIDGE_VERSION "0.4.3"
#define BRIDGE_COPYRIGHT "© Copyright 2026 NeDIAD | GNU/GPL-3.0 License | github.com/NeDIAD/Bridge"

namespace bridge {
    constexpr const char *kConsoleHeader = "Bridge " BRIDGE_VERSION "\n";
    constexpr const char *kCopyrightFooter = BRIDGE_COPYRIGHT "\n";
    constexpr const char *kArchiveReply =
        "You are connected via Bridge " BRIDGE_VERSION "\n" BRIDGE_COPYRIGHT "\n";
    constexpr const char *kDefaultReply =
        "You are bypassing Bridge " BRIDGE_VERSION "\n" BRIDGE_COPYRIGHT "\n";
}

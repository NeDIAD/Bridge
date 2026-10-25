#pragma once
#include <stdint.h>

namespace bridge {
    class SteamCallback {
        public:
            virtual void Run(void *data) = 0;
            virtual void Run(void *data, bool io_failure, uint64_t call) = 0;
            virtual int GetCallbackSizeBytes() = 0;
            
        protected:
            uint8_t flags_ = 2;  // k_ECallbackFlagsGameServer
            int callback_ = 143; // ValidateAuthTicketResponse_t
    };
    static_assert(sizeof(SteamCallback) == 12, "Steam i386 callback ABI");
    using RegisterCallbackFn = void (*)(SteamCallback *, int);
}

#pragma once
#include <stdint.h>

namespace bridge {
    enum class Phase : uint32_t { Cold, Installing, Waiting, Active, Failed, Stopped };
    class Lifecycle {
        uint32_t phase_ = uint32_t(Phase::Cold);
        
        public:
            Phase Get() const { return Phase(__atomic_load_n(&phase_, __ATOMIC_ACQUIRE)); }
            bool Move(Phase from, Phase to) {
                uint32_t expected = uint32_t(from);
                return __atomic_compare_exchange_n(&phase_, &expected, uint32_t(to), false,
                                           __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            }
            void Finish(Phase phase) { __atomic_store_n(&phase_, uint32_t(phase), __ATOMIC_RELEASE); }
            bool StopBeforeInstall() {
                if (Move(Phase::Waiting, Phase::Stopped))
                    return true;
                if (Move(Phase::Cold, Phase::Stopped))
                    return true;
                return Get() == Phase::Failed || Get() == Phase::Stopped;
            }
    };
}
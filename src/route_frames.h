#pragma once
#include "auth_route.h"

namespace bridge {
    class RouteFrames {
        struct Slot {
            uintptr_t frame;
            Selection selection;
            bool used;
        };
        Slot slots_[16]{};
        
        public:
            Selection *Begin(uintptr_t frame) {
                for (auto &slot : slots_) {
                    if (slot.used && slot.frame <= frame)
                        slot.used = false;
                }
                for (auto &slot : slots_) {
                    if (!slot.used) {
                        slot = {frame, {}, true};
                        return &slot.selection;
                    }
                }
                return nullptr;
            }
            bool Take(uintptr_t frame, Selection &selection) {
                for (auto &slot : slots_) {
                    if (slot.used && slot.frame == frame) {
                        selection = slot.selection;
                        slot.used = false;
                        return true;
                    }
                }
                return false;
            }
            void Cancel(uintptr_t frame) {
                Selection ignored{};
                Take(frame, ignored);
            }
    };
}

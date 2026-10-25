/*
    /ᐠ. ｡.ᐟ\ᵐᵉᵒʷˎˊ˗
    Credits: NeDIAD

    © Copyright 2026 NeDIAD | GNU/GPL-3.0 License
*/

#define _GNU_SOURCE 1
#include "auth_route.h"
#include "native_sessions.h"
#include "route_frames.h"
#include "lifecycle.h"
#include "native_patch_guard.h"
#include "native_lock_profile.h"
#include "steam_callback.h"
#include "version.h"
#include "session_tags.h"
#include "console_command.h"
#include "player_info.h"
#include <ISmmPlugin.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "profile.h"

static_assert(sizeof(void *) == 4, "Only Linux i386 SRCDS is supported");

SourceMM::ISmmAPI *g_SMAPI = nullptr;
SourceMM::ISmmPlugin *g_PLAPI = nullptr;
SourceMM::PluginId g_PLID = 0;
SourceHook::ISourceHook *g_SHPtr = nullptr;

SH_DECL_MANUALHOOK1_void(BridgeThink, 30, 0, 0, bool);
SH_DECL_MANUALHOOK1_void(BridgeSteamActivated, 36, 0, 0, bool);
SH_DECL_MANUALHOOK2_void(BridgeClientCommand, 6, 0, 0, edict_t *, const CCommand &);

void *operator new(size_t size) {
    void *p = malloc(size);
    if (!p)
        abort();
    return p;
}

void operator delete(void *p) noexcept {
    free(p);
}

void operator delete(void *p, size_t) noexcept {
    free(p);
}

namespace {
bridge::Api api{};
const bridge::Api *published_api = nullptr;
__thread bridge::RouteFrames routes{};
bridge::Lifecycle lifecycle;
bridge::SessionTags session_tags;
void *engine_interface = nullptr;
uint32_t client_command_hook = 0;
bool console_registered = false;

template <typename Function> Function Virtual(void *object, unsigned slot) {
    return reinterpret_cast<Function>((*static_cast<void ***>(object))[slot]);
}
void ConsoleVersion(const CCommand &) {
    g_SMAPI->ConPrint(bridge::kConsoleHeader);
    if (engine_interface) {
        using PlayerInfoFn = bool (*)(void *, int, bridge::PlayerInfo *);
        auto get_player = Virtual<PlayerInfoFn>(engine_interface, 108);
        for (int slot = 1; slot <= bridge::kAbsolutePlayerLimit; ++slot) {
            bridge::PlayerInfo player{};
            if (!get_player(engine_interface, slot, &player))
                continue;
            player.name[sizeof(player.name) - 1] = 0;
            for (char &c : player.name) {
                if (!c)
                    break;
                if (static_cast<unsigned char>(c) < 32 || c == 127)
                    c = ' ';
            }
            const uint32_t account = uint32_t(player.xuid);
            const uint32_t universe = uint32_t(player.xuid >> 56);
            const char *route = session_tags.IsArchive(player.xuid) ? "bridge" : "steam";
            g_SMAPI->ConPrintf("# %s  STEAM_%u:%u:%u %s\n", player.name, universe, account & 1u,
                               account >> 1, route);
        }
    }
    g_SMAPI->ConPrint(bridge::kCopyrightFooter);
}
BridgeConsoleCommand console_command(ConsoleVersion);
uint32_t bootstrap_hook = 0;
uint32_t activation_hook = 0;
uint32_t install_attempts = 0;
uint32_t retry_sources = 0;
uint32_t hooks_committed = 0;
char failure[256]{};
void *pinned_module = nullptr;
void *pinned_steam = nullptr;
void *pinned_engine = nullptr;
void *pinned_steam_api = nullptr;
uint32_t last_missing_modules = UINT32_MAX;
const char *discovery_wait = "not attempted";
const char *last_wait = nullptr;

void WaitReason(const char *reason) {
    __atomic_store_n(&discovery_wait, reason, __ATOMIC_RELEASE);
}

const bridge::Api *RuntimeApi() {
    return __atomic_load_n(&published_api, __ATOMIC_ACQUIRE);
}

void Log(const char *format, ...) {
    char message[768];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    fprintf(stderr, "[Bridge] %s\n", message);
}

int VerifyHook(void *self, const uint64_t *game, const void *ticket, int length, int *offset,
               uint64_t *identity, uint64_t peer) {
    const auto *runtime = RuntimeApi();
    if (!runtime)
        return bridge::kInvalid;
    const uintptr_t frame = *static_cast<const uintptr_t *>(__builtin_frame_address(0));
    auto *selection = routes.Begin(frame);
    if (!selection)
        return bridge::kInvalid;
    bridge::VerifyTrace trace{};
    const int result = bridge::Verify(*runtime, *selection, self, game, ticket, length, offset,
                                      identity, peer, trace);
    if (result != bridge::kOK || !identity || *identity != peer)
        routes.Cancel(frame);
    if (trace.original_result != bridge::kOK)
        Log("ticket check: steamid=%llu expected_appid=%llu original_result=%d "
            "archive_result=%d final_result=%d bytes=%d",
            (unsigned long long)peer, (unsigned long long)trace.expected_game,
            trace.original_result, trace.archive_result, result, length);
    return result;
}

int RegisterHook(void *self, int mode, const uint64_t *game, const void *ticket, int length,
                 int offset, uint64_t peer, uint32_t *handle, void *extra) {
    const auto *runtime = RuntimeApi();
    if (!runtime)
        return bridge::kInvalid;
    const uintptr_t frame = *static_cast<const uintptr_t *>(__builtin_frame_address(0));
    bridge::Selection selection{};
    if (!routes.Take(frame, selection))
        return bridge::kInvalid;
    bool routed = false;
    const int result = bridge::Register(*runtime, selection, self, mode, game, ticket, length,
                                        offset, peer, handle, extra, routed);
    if (result == bridge::kOK && mode == 1 && game && *game == bridge::kServerApp) {
        if (!session_tags.Set(peer, routed))
            Log("connection route label table is full");
    }
    if (result == bridge::kDuplicate)
        Log("duplicate auth session: steamid=%llu result=2 (DuplicateRequest)",
            (unsigned long long)peer);
    if (routed)
        Log("archive session started: steamid=%llu appid=4465480; awaiting Steam validation",
            (unsigned long long)peer);
    return result;
}

void EndHook(void *self, uint64_t peer, const uint64_t *game) {
    const auto *runtime = RuntimeApi();
    if (runtime) {
        bridge::End(*runtime, self, peer, game);
        session_tags.Remove(peer);
    }
}

void ObserveAuth(const void *data) {
    if (!data)
        return;
    uint64_t identity = 0, owner = 0;
    uint32_t response = 0;
    memcpy(&identity, data, 8);
    memcpy(&response, static_cast<const char *>(data) + 8, 4);
    memcpy(&owner, static_cast<const char *>(data) + 12, 8);
    Log("Steam ValidateAuthTicketResponse: steamid=%llu response=%u owner=%llu (%s)",
        (unsigned long long)identity, response, (unsigned long long)owner,
        response == 0 ? "OK" : "REJECTED");
}
class AuthObserver final : public bridge::SteamCallback {
public:
    void Run(void *data) override { ObserveAuth(data); }
    void Run(void *data, bool io_failure, uint64_t) override {
        if (!io_failure)
            ObserveAuth(data);
    }
    int GetCallbackSizeBytes() override { return 20; }
};
AuthObserver observer;
bridge::RegisterCallbackFn register_callback = nullptr;
bool observer_registered = false;
uintptr_t auth_mutex = 0, steam_base = 0;
bridge::NativePatchGuard::MutexFn native_trylock = nullptr, native_unlock = nullptr;

struct Module {
    uintptr_t base;
    const ElfW(Phdr) * headers;
    unsigned count;
    char path[4096];
    unsigned matches;
};

struct Modules {
    Module steam;
    Module engine;
    Module steam_api;
};
Module isolated_steam{};

int FindModules(dl_phdr_info *info, size_t, void *context) {
    auto &modules = *static_cast<Modules *>(context);
    const char *path = info->dlpi_name;
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    Module *module = nullptr;
    if (!strcmp(name, "engine.so") || !strcmp(name, "engine_srv.so"))
        module = &modules.engine;
    if (!strcmp(name, "libsteam_api.so"))
        module = &modules.steam_api;
    if (module) {
        module->base = info->dlpi_addr;
        module->headers = info->dlpi_phdr;
        module->count = info->dlpi_phnum;
        snprintf(module->path, sizeof(module->path), "%s", path);
        ++module->matches;
    }
    return 0;
}

int PinIsolatedSteam(const char *path, uintptr_t expected_base, Module &steam, const char *source) {
    for (Lmid_t ns = 0; ns < 16; ++ns) {
        void *handle = dlmopen(ns, path, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE);
        if (!handle)
            continue;
        link_map *map = nullptr;
        if (dlinfo(handle, RTLD_DI_LINKMAP, &map) || !map ||
            uintptr_t(map->l_addr) != expected_base) {
            dlclose(handle);
            continue;
        }
        const auto *elf = reinterpret_cast<const Elf32_Ehdr *>(expected_base);
        if (memcmp(elf->e_ident, ELFMAG, SELFMAG) || elf->e_ident[EI_CLASS] != ELFCLASS32 ||
            elf->e_phentsize != sizeof(Elf32_Phdr) || !elf->e_phnum || elf->e_phnum > 128 ||
            elf->e_phoff > 65536) {
            dlclose(handle);
            snprintf(failure, sizeof(failure), "active Steamclient has invalid ELF headers");
            return -1;
        }
        pinned_steam = handle;
        steam.base = expected_base;
        steam.headers = reinterpret_cast<const Elf32_Phdr *>(steam.base + elf->e_phoff);
        steam.count = elf->e_phnum;
        steam.matches = 1;
        snprintf(steam.path, sizeof(steam.path), "%s", path);
        Log("found Steamclient through %s in loader namespace %ld: %s", source, long(ns),
            steam.path);
        return 1;
    }
    snprintf(failure, sizeof(failure),
             "cannot pin mapped Steamclient at %s in an existing loader namespace", path);
    return -1;
}

int FindIsolatedSteam(const Module &steam_api, Module &steam) {
    if (isolated_steam.matches) {
        steam = isolated_steam;
        return 1;
    }
    
    if (steam_api.matches != 1) {
        WaitReason("waiting for a single libsteam_api.so");
        return 0;
    }
    
    if (!pinned_steam_api)
        pinned_steam_api = dlopen(steam_api.path, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE);
    if (!pinned_steam_api) {
        snprintf(failure, sizeof(failure), "cannot pin existing libsteam_api.so");
        return -1;
    }
    
    using UserFn = int (*)();
    using FindFn = void *(*)(int, const char *);
    auto user = reinterpret_cast<UserFn>(dlsym(pinned_steam_api, "SteamGameServer_GetHSteamUser"));
    auto find = reinterpret_cast<FindFn>(
        dlsym(pinned_steam_api, "SteamInternal_FindOrCreateGameServerInterface"));
    void *client = nullptr;
    if (user && find) {
        const int handle = user();
        if (handle <= 0) {
            WaitReason("SteamGameServer user is not initialized");
            return 0;
        }
        client = find(handle, "SteamGameServer014");
        if (!client) {
            WaitReason("SteamGameServer014 is not available yet");
            return 0;
        }
    } else {
        using CreateFn = void *(*)(const char *);
        auto create =
            reinterpret_cast<CreateFn>(dlsym(pinned_steam_api, "SteamInternal_CreateInterface"));
        if (!create) {
            snprintf(failure, sizeof(failure),
                     "required Steam API interface exports are unavailable");
            return -1;
        }
        client = create("SteamClient020");
        if (!client) {
            WaitReason("SteamClient020 is not available yet");
            return 0;
        }
    }
    const void *method = (*static_cast<void ***>(client))[0];
    Dl_info info{};
    if (!dladdr(method, &info) || !info.dli_fbase || !info.dli_fname) {
        snprintf(failure, sizeof(failure), "cannot locate initialized Steam interface code");
        return -1;
    }
    const int result =
        PinIsolatedSteam(info.dli_fname, uintptr_t(info.dli_fbase), steam, "Steam game-server API");
    if (result > 0)
        isolated_steam = steam;
    return result;
}

bool DiscoverModules(Modules &modules) {
    dl_iterate_phdr(FindModules, &modules);
    Module active{};
    const int found = FindIsolatedSteam(modules.steam_api, active);
    if (found < 0)
        return false;
    modules.steam = active;
    if (found > 0 && !register_callback) {
        register_callback = reinterpret_cast<bridge::RegisterCallbackFn>(
            dlsym(pinned_steam_api, "SteamAPI_RegisterCallback"));
        if (!register_callback) {
            snprintf(failure, sizeof(failure), "SteamAPI_RegisterCallback export is unavailable");
            return false;
        }
    }
    return true;
}

bool Contains(const Module &module, uintptr_t address, size_t length, unsigned flags) {
    if (length > UINTPTR_MAX - address)
        return false;
    for (unsigned i = 0; i < module.count; ++i) {
        const auto &p = module.headers[i];
        if (p.p_type == PT_LOAD && (p.p_flags & flags) == flags &&
            address >= module.base + p.p_vaddr &&
            address + length <= module.base + p.p_vaddr + p.p_memsz)
            return true;
    }
    return false;
}

bool BuildIdMatches(const Module &module, const unsigned char expected[20]) {
    for (unsigned i = 0; i < module.count; ++i) {
        const auto &p = module.headers[i];
        if (p.p_type != PT_NOTE)
            continue;
        uintptr_t pos = module.base + p.p_vaddr;
        const uintptr_t end = pos + p.p_memsz;
        if (!Contains(module, pos, p.p_memsz, PF_R))
            continue;
        while (pos <= end && end - pos >= sizeof(Elf32_Nhdr)) {
            Elf32_Nhdr note;
            memcpy(&note, reinterpret_cast<void *>(pos), sizeof(note));
            pos += sizeof(note);
            const uint64_t name_size = (uint64_t(note.n_namesz) + 3) & ~uint64_t(3);
            const uint64_t desc_size = (uint64_t(note.n_descsz) + 3) & ~uint64_t(3);
            if (name_size + desc_size > end - pos)
                break;
            if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 && note.n_descsz == 20 &&
                !memcmp(reinterpret_cast<void *>(pos), "GNU", 4))
                return !memcmp(reinterpret_cast<void *>(pos + name_size), expected, 20);
            pos += uintptr_t(name_size + desc_size);
        }
    }
    return false;
}

struct Patch {
    unsigned char *site;
    unsigned char replacement[5];
};
Patch patches[3]{};

bool CommitPatches() {
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || (page_size & (page_size - 1))) {
        snprintf(failure, sizeof(failure), "invalid system page size");
        return false;
    }
    uintptr_t pages[10]{};
    unsigned page_count = 0;
    
    for (const auto &patch : patches) {
        const uintptr_t begin = uintptr_t(patch.site) & ~(uintptr_t(page_size) - 1);
        const uintptr_t end = (uintptr_t(patch.site) + 4) & ~(uintptr_t(page_size) - 1);
        for (uintptr_t page = begin; page <= end; page += uintptr_t(page_size)) {
            bool found = false;
            for (unsigned j = 0; j < page_count; ++j)
                found |= pages[j] == page;
            if (!found)
                pages[page_count++] = page;
        }
    }
    
    bridge::NativePatchGuard guard(reinterpret_cast<void *>(auth_mutex), native_trylock,
                                   native_unlock);
    if (!guard.Acquire()) {
        snprintf(failure, sizeof(failure), "%s (errno=%d); no instructions changed",
                 guard.Failure(), guard.Error());
        return false;
    }
    
    bool okay = true;
    unsigned writable = 0;
    
    if (memcmp(reinterpret_cast<void *>(steam_base + kBeginCodeRva), kBeginCode,
               sizeof(kBeginCode)) ||
        memcmp(reinterpret_cast<void *>(steam_base + kEndCodeRva), kEndCode, sizeof(kEndCode)))
        okay = false;
    for (unsigned i = 0; i < 3; ++i) {
        if (memcmp(patches[i].site - 8, kSites[i].context, sizeof(kSites[i].context)))
            okay = false;
    }
    if (okay) {
        for (; writable < page_count; ++writable) {
            if (mprotect(reinterpret_cast<void *>(pages[writable]), page_size,
                         PROT_READ | PROT_WRITE | PROT_EXEC)) {
                okay = false;
                break;
            }
        }
    }
    bool patched = false;
    if (okay) {
        for (const auto &patch : patches) {
            memcpy(patch.site, patch.replacement, 5);
        }
        patched = true;
    }
    const bool synchronized = !patched || guard.Sync();
    for (unsigned i = 0; i < writable; ++i) {
        if (mprotect(reinterpret_cast<void *>(pages[i]), page_size, PROT_READ | PROT_EXEC))
            okay = false;
    }
    if (patched)
        __atomic_store_n(&hooks_committed, 1u, __ATOMIC_RELEASE);
    
    guard.Release();
    if (!synchronized) {
        snprintf(failure, sizeof(failure), "%s (errno=%d); hooks committed, restart required",
                 guard.Failure(), guard.Error());
        return false;
    }
    if (!okay)
        snprintf(
            failure, sizeof(failure), "%s",
            __atomic_load_n(&hooks_committed, __ATOMIC_ACQUIRE)
                ? "hooks committed but code synchronization or RX restore failed; restart required"
                : "hook transaction rejected before code writes; restart required");
    return okay;
}

int Install() {
    __atomic_add_fetch(&install_attempts, 1u, __ATOMIC_RELAXED);
    Modules modules{};
    if (!DiscoverModules(modules))
        return -1;
    if (modules.steam.matches == 0 || modules.engine.matches == 0) {
        const uint32_t missing = (modules.engine.matches ? 0u : 1u) |
                                 (modules.steam.matches ? 0u : 2u) |
                                 (modules.steam_api.matches ? 0u : 4u);
        const char *reason = __atomic_load_n(&discovery_wait, __ATOMIC_ACQUIRE);
        if (missing != last_missing_modules || reason != last_wait) {
            last_missing_modules = missing;
            last_wait = reason;
            Log("waiting for modules: engine=%u steamclient=%u steam_api=%u; %s",
                modules.engine.matches, modules.steam.matches, modules.steam_api.matches, reason);
        }
        return 0;
    }
    if (modules.steam.matches != 1 || modules.engine.matches != 1) {
        snprintf(failure, sizeof(failure), "multiple engine/steamclient modules loaded");
        return -1;
    }
    
    if (!pinned_steam)
        pinned_steam = dlopen(modules.steam.path, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE);
    
    if (!pinned_engine)
        pinned_engine = dlopen(modules.engine.path, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE);
    
    if (!pinned_steam || !pinned_engine) {
        snprintf(failure, sizeof(failure), "cannot pin native engine/Steamclient dependencies");
        return -1;
    }
    
    modules = {};
    if (!DiscoverModules(modules))
        return -1;
    
    if (modules.steam.matches != 1 || modules.engine.matches != 1) {
        snprintf(failure, sizeof(failure), "module mappings changed during initialization");
        return -1;
    }
    
    const Module &steam = modules.steam;
    const Module &engine = modules.engine;
    
    if (!BuildIdMatches(steam, kSteamBuildId) || !BuildIdMatches(engine, kEngineBuildId)) {
        snprintf(failure, sizeof(failure),
                 "unsupported engine/steamclient build; see src/profile.h");
        return -1;
    }
    // Reject the original bypass if it is still installed. No engine writes.
    const uintptr_t dispatch = engine.base + 0x18a2ba;
    if (!Contains(engine, dispatch, 7, PF_R | PF_X) ||
        memcmp(reinterpret_cast<void *>(dispatch), "\xff\x24\x85", 3)) {
        snprintf(failure, sizeof(failure), "engine authentication dispatch is modified");
        return -1;
    }
    uintptr_t table = 0;
    memcpy(&table, reinterpret_cast<void *>(dispatch + 3), 4);
    if (!Contains(engine, table, 24, PF_R) ||
        reinterpret_cast<const uintptr_t *>(table)[4] != engine.base + 0x18a3d8 ||
        reinterpret_cast<const uintptr_t *>(table)[0] != engine.base + 0x18a498) {
        snprintf(failure, sizeof(failure),
                 "remove csgo_steamfix and restart: engine authentication table is modified");
        return -1;
    }

    if (!Contains(steam, steam.base + kAuthMutexRva, sizeof(pthread_mutex_t), PF_R | PF_W) ||
        !Contains(steam, steam.base + kBeginCodeRva, sizeof(kBeginCode), PF_R | PF_X) ||
        !Contains(steam, steam.base + kEndCodeRva, sizeof(kEndCode), PF_R | PF_X) ||
        memcmp(reinterpret_cast<void *>(steam.base + kBeginCodeRva), kBeginCode,
               sizeof(kBeginCode)) ||
        memcmp(reinterpret_cast<void *>(steam.base + kEndCodeRva), kEndCode, sizeof(kEndCode))) {
        snprintf(failure, sizeof(failure), "native auth lock proof does not match current code");
        return -1;
    }
    
    auth_mutex = steam.base + kAuthMutexRva;
    steam_base = steam.base;
    
    native_trylock = reinterpret_cast<bridge::NativePatchGuard::MutexFn>(
        dlsym(pinned_steam, "pthread_mutex_trylock"));
    native_unlock = reinterpret_cast<bridge::NativePatchGuard::MutexFn>(
        dlsym(pinned_steam, "pthread_mutex_unlock"));
    
    if (!native_trylock || !native_unlock) {
        snprintf(failure, sizeof(failure),
                 "native Steamclient pthread mutex exports are unavailable");
        return -1;
    }
    void *hooks[3] = {reinterpret_cast<void *>(VerifyHook), reinterpret_cast<void *>(RegisterHook),
                      reinterpret_cast<void *>(EndHook)};
    for (unsigned i = 0; i < 3; ++i) {
        const auto &profile = kSites[i];
        const uintptr_t site = steam.base + profile.rva;
        if (!Contains(steam, site - 8, sizeof(profile.context), PF_R | PF_X) ||
            memcmp(reinterpret_cast<void *>(site - 8), profile.context, sizeof(profile.context))) {
            snprintf(failure, sizeof(failure),
                     "hook %u does not match original code; another patch or wrong binary", i);
            return -1;
        }
        auto &patch = patches[i];
        patch.site = reinterpret_cast<unsigned char *>(site);
        patch.replacement[0] = 0xe8;
        const uint32_t displacement = uint32_t(uintptr_t(hooks[i]) - (site + 5));
        memcpy(patch.replacement + 1, &displacement, 4);
    }
    api = {reinterpret_cast<bridge::VerifyFn>(steam.base + 0x1f3360),
           reinterpret_cast<bridge::RegisterFn>(steam.base + 0x1f3810),
           reinterpret_cast<bridge::EndFn>(steam.base + 0x1f3f70), bridge::NativeSessionExists};

    if (!pinned_module) {
        Dl_info own{};
        if (!dladdr(reinterpret_cast<void *>(VerifyHook), &own) ||
            !(pinned_module = dlopen(own.dli_fname, RTLD_NOW | RTLD_NODELETE))) {
            snprintf(failure, sizeof(failure), "cannot pin extension for safe hook lifetime");
            return -1;
        }
    }
    
    __atomic_store_n(&published_api, static_cast<const bridge::Api *>(&api), __ATOMIC_RELEASE);
    if (!CommitPatches())
        return -1;
    
    if (!observer_registered) {
        register_callback(&observer, 143);
        observer_registered = true;
    }
    
    Log("Bridge " BRIDGE_VERSION " installed");
    Log("steamclient=%s", steam.path);
    
    return 1;
}

class Bridge final : public SourceMM::ISmmPlugin, public SourceMM::IMetamodListener {
    void DropConsole() {
        const uint32_t hook = __atomic_exchange_n(&client_command_hook, 0u, __ATOMIC_ACQ_REL);
        
        if (hook)
            SH_REMOVE_HOOK_ID(int(hook));
        
        if (console_registered) {
            g_SMAPI->UnregisterConCommandBase(this, &console_command);
            console_registered = false;
        }
    }
    bool SetupConsole() {
        auto engine_factory = g_SMAPI->GetEngineFactory(false);
        auto server_factory = g_SMAPI->GetServerFactory(false);
        engine_interface = engine_factory ? engine_factory("VEngineServer023", nullptr) : nullptr;
        void *cvar = engine_factory ? engine_factory("VEngineCvar007", nullptr) : nullptr;
        void *clients = server_factory ? server_factory("ServerGameClients004", nullptr) : nullptr;
        
        if (!engine_interface || !cvar || !clients || !g_SHPtr) {
            snprintf(failure, sizeof(failure),
                     "cannot get engine/client interfaces for bridge command");
            return false;
        }
        
        using FindFn = ConCommandBase *(*)(void *, const char *);
        using AllocateFn = int (*)(void *);
        
        if (Virtual<FindFn>(cvar, 14)(cvar, "bridge")) {
            snprintf(failure, sizeof(failure), "console command bridge is already registered");
            return false;
        }
        
        bridge::command_dll_id = Virtual<AllocateFn>(cvar, 9)(cvar);
        
        if (bridge::command_dll_id < 0 ||
            !g_SMAPI->RegisterConCommandBase(this, &console_command)) {
            snprintf(failure, sizeof(failure), "cannot register bridge console command");
            return false;
        }
        
        console_registered = true;
        const int hook = SH_ADD_MANUALHOOK(BridgeClientCommand, clients,
                                           SH_MEMBER(this, &Bridge::OnClientCommand), false);
        __atomic_store_n(&client_command_hook, uint32_t(hook), __ATOMIC_RELEASE);
        
        if (!hook) {
            DropConsole();
            snprintf(failure, sizeof(failure), "cannot hook client bridge command");
            return false;
        }
        
        return true;
    }
    
    void DropBootstrap() {
        const uint32_t hook = __atomic_exchange_n(&bootstrap_hook, 0u, __ATOMIC_ACQ_REL);
        const uint32_t activated = __atomic_exchange_n(&activation_hook, 0u, __ATOMIC_ACQ_REL);
        
        if (hook)
            SH_REMOVE_HOOK_ID(int(hook));
        
        if (activated)
            SH_REMOVE_HOOK_ID(int(activated));
    }
    
    void Retry(const char *source, uint32_t bit) {
        if (!lifecycle.Move(bridge::Phase::Waiting, bridge::Phase::Installing))
            return;
        if (!(__atomic_fetch_or(&retry_sources, bit, __ATOMIC_RELAXED) & bit))
            Log("startup retry from %s", source);
        
        const int result = Install();
        if (result != 0)
            DropBootstrap();
        
        if (result < 0)
            Log("ERROR: %s", failure);
        
        lifecycle.Finish(result == 0  ? bridge::Phase::Waiting
                         : result > 0 ? bridge::Phase::Active
                                      : bridge::Phase::Failed);
    }

public:
    bool Load(SourceMM::PluginId id, SourceMM::ISmmAPI *ismm, char *error, size_t length, bool late) override {
        if (late) {
            snprintf(error, length, "late load is unavailable, restart server to use Bridge");
            Log("ERROR: %s", error);
            return false;
        }
        if (!ismm || !lifecycle.Move(bridge::Phase::Cold, bridge::Phase::Installing)) {
            snprintf(error, length, "plugin initialization unavailable, restart server");
            return false;
        }
        PLUGIN_SAVEVARS();
        failure[0] = 0;
        
        if (!SetupConsole()) {
            lifecycle.Finish(bridge::Phase::Failed);
            snprintf(error, length, "%s", failure);
            Log("ERROR: %s", failure);
            return false;
        }
        
        const int result = Install();
        if (result < 0) {
            DropConsole();
            lifecycle.Finish(bridge::Phase::Failed);
            snprintf(error, length, "%s", failure);
            Log("ERROR: %s", failure);
            return false;
        }
        
        if (result == 0) {
            auto factory = g_SHPtr ? ismm->GetServerFactory(false) : nullptr;
            void *server_dll = factory ? factory("ServerGameDLL005", nullptr) : nullptr;
            const int hook = server_dll ? SH_ADD_MANUALHOOK(BridgeThink, server_dll,
                                                            SH_MEMBER(this, &Bridge::OnThink), true)
                                        : 0;
            __atomic_store_n(&bootstrap_hook, uint32_t(hook), __ATOMIC_RELEASE);
            
            const int activated =
                server_dll ? SH_ADD_MANUALHOOK(BridgeSteamActivated, server_dll,
                                               SH_MEMBER(this, &Bridge::OnSteamActivated), true)
                           : 0;
            __atomic_store_n(&activation_hook, uint32_t(activated), __ATOMIC_RELEASE);
            
            if (!hook || !activated) {
                DropBootstrap();
                DropConsole();
                snprintf(failure, sizeof(failure),
                         "cannot install Steam activation/Think startup hooks");
                lifecycle.Finish(bridge::Phase::Failed);
                snprintf(error, length, "%s", failure);
                Log("ERROR: %s", failure);
                return false;
            }
            
            Log("waiting for host Steam activation");
        }
        
        ismm->AddListener(this, this);
        lifecycle.Finish(result ? bridge::Phase::Active : bridge::Phase::Waiting);
        return true;
    }
    
    void AllPluginsLoaded() override { Retry("AllPluginsLoaded", 1); }
    bool QueryRunning(char *error, size_t length) override {
        const auto phase = lifecycle.Get();
        if (phase == bridge::Phase::Waiting && error && length) {
            snprintf(error, length, "hooks not installed: %s; attempts=%u retry_sources=0x%x",
                     __atomic_load_n(&discovery_wait, __ATOMIC_ACQUIRE),
                     __atomic_load_n(&install_attempts, __ATOMIC_RELAXED),
                     __atomic_load_n(&retry_sources, __ATOMIC_RELAXED));
            return false;
        }
        if (phase != bridge::Phase::Active && error && length)
            snprintf(error, length, "%s",
                     phase == bridge::Phase::Failed
                         ? failure
                         : "Bridge initialization is unavailable or in progress");
        return phase == bridge::Phase::Active;
    }
    
    bool Unload(char *error, size_t length) override {
        if (__atomic_load_n(&hooks_committed, __ATOMIC_ACQUIRE) || !lifecycle.StopBeforeInstall()) {
            snprintf(error, length, "active/initializing Bridge requires a server process restart");
            return false;
        }
        
        DropBootstrap();
        DropConsole();
        
        return true;
    }
    
    bool Pause(char *error, size_t length) override {
        snprintf(error, length, "Bridge patches cannot be paused; restart to remove the plugin");
        return false;
    }
    bool Unpause(char *, size_t) override { return true; }
    const char *GetAuthor() override { return "NeDIAD"; }
    const char *GetName() override { return "Bridge"; }
    const char *GetDescription() override { return "Proper fix for archived CS:GO, with compatibility layer."; }
    const char *GetURL() override { return "github.com/NeDIAD/bridge"; }
    const char *GetLicense() override { return "GPL-3.0"; }
    const char *GetVersion() override { return BRIDGE_VERSION; }
    const char *GetDate() override { return "2026-10-25"; }
    const char *GetLogTag() override { return "bridge"; }
    
    void OnLevelInit(const char *, const char *, const char *, const char *, bool, bool) override {
        Retry("LevelInit", 2);
    }
    
    void OnThink(bool) {
        Retry("Think", 4);
        RETURN_META(MRES_IGNORED);
    }
    
    void OnSteamActivated(bool active) {
        if (active)
            Retry("SteamAPIActivated", 8);
        RETURN_META(MRES_IGNORED);
    }
    
    void OnClientCommand(edict_t *client, const CCommand &args) {
        const char *name = args.Arg0();
        const char expected[] = "bridge";
        unsigned i = 0;
        for (; name[i] && expected[i]; ++i) {
            const char c = name[i] >= 'A' && name[i] <= 'Z' ? char(name[i] + ('a' - 'A')) : name[i];
            if (c != expected[i])
                break;
        }
        if (name[i] || expected[i] || !client)
            RETURN_META(MRES_IGNORED);
        // IVEngineServer023::GetClientSteamID - slot 129
        using SteamIdFn = const void *(*)(void *, const edict_t *, bool);
        const void *identity =
            Virtual<SteamIdFn>(engine_interface, 129)(engine_interface, client, false);
        uint64_t peer = 0;
        if (identity)
            memcpy(&peer, identity, sizeof(peer));
        const char *reply =
            session_tags.IsArchive(peer) ? bridge::kArchiveReply : bridge::kDefaultReply;
        g_SMAPI->ClientConPrintf(client, "%s", reply);
        RETURN_META(MRES_SUPERCEDE);
    }
};

Bridge plugin;
}

extern "C" __attribute__((visibility("default"))) void *CreateInterface(const char *name,
                                                                        int *code) {
    if (name && !strcmp(name, METAMOD_PLAPI_NAME)) {
        if (code)
            *code = META_IFACE_OK;
        return static_cast<SourceMM::ISmmPlugin *>(&plugin);
    }
    if (code)
        *code = META_IFACE_FAILED;
    return nullptr;
}

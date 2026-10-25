# Reverse engineering notes

Addresses are RVAs in the supplied ELF files. Ghidra imported Steamclient at
image base 0x10000: decompiler addresses equal RVA + 0x10000.

Exact SHA-256 values, build IDs and call contexts are recorded in profile.json.
The local Ghidra project used during analysis is not distributed in this repository.

## Engine

- 0x18a2ab calls ISteamGameServer::BeginAuthSession through vtable +0x68.
- 0x18a2ba dispatches through the table at 0x501b64.
- Entry 0 points to 0x18a498; entry 4 points to wrong-game rejection at 0x18a3d8.
- Replacing entry 4 changes admission, without making Steam auth succeed.

The plugin verifies this table and never writes to engine.so.

## Steamclient

Function names below describe recovered behavior; they are not exported names.

| RVA | Recovered purpose |
|---|---|
| 0x4890e0 | GameServer BeginAuthSession, protected by native lock |
| 0x1f3360 | Local ticket check with expected CGameID, output SteamID and offset |
| 0x1f3810 | Register session and schedule sending the native auth list |
| 0x1f3f70 | Remove sessions matching SteamID and CGameID |
| 0x1f4120 | Query license through a session matching SteamID and CGameID |
| 0x239cf0 | Process native Steam auth response and issue callback 143 |
| 0x1f2960 | Native callback delivery |

BeginAuthSession reads AppId from object +0x1a04 and masks to 24 bits. It invokes
the local checker, compares the resulting SteamID to the claimed identity,
checks account type, and then registers the session. Registration copies CGameID
and SteamID into a vector at object +0x1700 (count at +0x170c). Entry size is
0x8c; peer SteamID is at +8 and CGameID at +0x10.

The checker uses the same expected CGameID for the session header and ownership
ticket. Changing just a return value or one comparison is not equivalent to
processing a different application's ticket. The registration choice must also
change: 0x1f4810 serializes each session's saved CGameID into the auth list.

The response processor updates native session state using the ticket identifier.
Its existing delivery call sends the original 20-byte callback: SteamID64,
uint32 response, owner SteamID64. The plugin logs this callback and passes it
on unchanged. Native routing to the server object is retained.

| Call RVA | Original target | Wrapper |
|---|---|---|
| 0x4891aa | 0x1f3360 | Retry WrongGame only for 730 to 4465480 |
| 0x489325 | 0x1f3810 | Register with selected CGameID |
| 0x48992d | 0x1f3f70 | End sessions for both AppIds |
| 0x48905a | 0x1f4120 | Archive session fallback only for NoAuth |
| 0x239e73 | 0x1f2960 | Log and forward unchanged callback |

The selection is per-thread, bound to server, ticket pointer/length, peer and
offset, and consumed once. The global GameServer AppId is never changed.

## Unverified backend behavior

Static analysis does not prove that Steam accepts an AppId 4465480 auth session
from a GameServer registered for 730. A real archived client ticket and running
server are required. Local checker/BeginAuthSession success is not identity
confirmation. Negative callbacks and timeouts are not converted to success.

Relevant decompiler output: begin-auth.c, end-auth.c, session-events.c,
validate-response.c and gameserver-response.c.


## Metamod migration and duplicate account guard (0.2.0)

The plugin now implements the official Metamod ISmmPlugin API 16, exporting
CreateInterface("ISmmPlugin"). SourceMod is not required. The public SDK is
vendored, unmodified, from the commit recorded in third_party/metamod-source.
A temporary official SourceHook GameFrame post-hook handles delayed Steamclient
initialization; CSGO ServerGameDLL005 GameFrame is slot 4, verified against the
public hl2sdk/csgo eiface.h and the supplied csgo/server.so interface string.

The original registrar (0x1f3810) treats a session as a duplicate only when both
its CGameID and SteamID match and (entry.mode & ~2) == 1 (states 1 or 3).
Bridge checks that same native vector for the other supported CGameID before
calling the registrar. This check remains inside the original lock held by
GameServer::BeginAuthSession (0x4890e0), as does the original registration.
There is no independently maintained identity/session map and no extra native
session is inserted for a rejected cross-AppId duplicate. Same-AppId duplicate
results remain the original registrar's result. EndAuthSession removes both
keys; a subsequent valid connection is allowed again.

The core policy and the compiled plugin have regression tests for 4465480->730,
730->4465480, pending/active native states 1/3, same-AppId native duplicates,
different accounts, and reconnect after EndAuthSession. The compiled bootstrap
SourceHook delegate and its self-removal are also exercised with mocks.


## Concurrency hardening (0.3.0)

See RACE_REVIEW.md for findings, protocol details and validation limits.
Native lock coverage is checked by tests/verify_native_lock.py. Bridge now
publishes its immutable native API through an acquire/release pointer and uses
an atomic lifecycle. Committed hooks cannot be hot-unloaded. All thread parking
and instruction changes are one bounded startup transaction. Per-thread routes
are additionally keyed by the pinned caller's EBP frame to preserve nesting.

## Isolated loader namespace discovery (0.3.1)

The supplied libsteam_api.so exports SteamInternal_CreateInterface (RVA 0x1b190).
It uses an existing GameServer Steamclient handle preferentially, falling back
to the client handle; absent handles return null without initializing Steam.
The exported __wrap_dlmopen at 0x330a0 forwards the requested namespace to
dlmopen. Calls at 0x1a483 and 0x1a58e pass a namespace computed as the negative
of a boolean, permitting LM_ID_NEWLM (-1), and RTLD_NOW (2). Thus the original
base-namespace dl_iterate_phdr search is insufficient for supported loading
paths. This proves a supported failure path, not which path ran on a remote host.

When Steamclient is absent from the base namespace, Bridge now resolves
SteamClient017 through the existing Steam API library, obtains an actual
interface method's module with dladdr, and probes existing glibc namespace IDs
0..15 with NOLOAD | NODELETE | NOW. dlinfo on each real handle must confirm the
same load base. ELF metadata, build IDs, original instructions and the engine
auth dispatch remain checked before installing any patch. All loader work is
before thread quiescence. No private Steam API offsets are used at runtime.

Reference: https://man7.org/linux/man-pages/man3/dlopen.3.html (dlmopen isolation,
NOLOAD, NODELETE and the glibc limit of 16 namespaces).
Compiled emulation covers isolated discovery, delayed API initialization,
wrong build rejection and a namespace handle for the wrong load base. Actual
glibc namespace behavior and live SRCDS still require a Linux host.

## Maps fallback independent of Steam API (0.3.2)

A live host reported engine=1, steamclient=0, steam_api=1 while its process maps
contained a readable offset-zero mapping of serverfiles/bin/steamclient.so.
The 0.3.1 discovery path could still wait indefinitely when the interface
symbol was absent or returned null. The exact reason for the host's null API
interface has not been established; it no longer controls maps discovery.

Discovery now inventories /proc/self/maps when the base namespace cannot see
Steamclient and the API interface is unavailable. src/steam_mapping.h parses
only readable, offset-zero steamclient.so file mappings. Bounds/overflow,
truncated lines and ambiguous escaped paths are rejected; spaces are preserved.
The mapping is never dereferenced until an existing NOLOAD namespace handle
has been obtained and dlinfo confirms the same load base. Multiple distinct
candidates are rejected before patching. Pinned metadata is cached for the
subsequent validation snapshot, avoiding repeated reference acquisition.

Compiled CPU emulation covers a null API interface, missing API export,
delayed mapping discovery through the actual GameFrame delegate, wrong build,
ambiguous copies and unreadable process maps. Parser tests include the live
host's original maps line. All loader/procfs work precedes thread quiescence;
the native authentication, duplicate guard and patch transaction are unchanged.
Real glibc/procfs operation and Steam backend acceptance are not tested here.

## Steam activation lifecycle without maps inventory (0.3.3)

Online primary references:
- https://github.com/alliedmodders/hl2sdk/blob/csgo/public/eiface.h
  documents Think as running even when no level is loaded and
  GameServerSteamAPIActivated(bool) as post-level Steam API activation.
- https://github.com/psychonic/d2fixups/blob/master/d2fixups.cpp
  uses a SourceHook post-hook for GameServerSteamAPIActivated.
- https://partner.steamgames.com/doc/api/steam_gameserver
  describes the host-owned game-server Steam API lifecycle.

The 0.3.1/0.3.2 remote logs do not establish that any retry ran after Load.
Adding another discovery method cannot fix a callback which is not reached.
GameFrame depends on game simulation and is unsuitable as the only repeated
bootstrap callback for a hibernating server. The exact remote callback sequence
was not observed; the new status records attempts and reached retry sources.

The maps fallback and src/steam_mapping.h were removed. Two temporary official
SourceHook post-hooks replace GameFrame: SteamAPIActivated and Think. False
(deactivation) notifications do not trigger initialization. Successful install,
error or pending unload removes both hooks; a partial registration failure also
removes the first hook. The existing atomic lifecycle serializes retries.

For an isolated Steamclient, use the already initialized host game-server user
with SteamGameServer_GetHSteamUser and SteamInternal_FindOrCreateGameServerInterface
requesting SteamGameServer014. The supplied engine contains SteamClient020 and
SteamGameServer014 strings; it does not request the previously hardcoded 017.
Only when the game-server accessors are absent, use SteamInternal_CreateInterface
with SteamClient020. No Steam init/logon/user creation is performed. Module
identity comes from dladdr of an actual interface method, followed by a real
NOLOAD/NODELETE handle whose dlinfo load base must match. Native code checks and
the stopped-thread patch transaction are unchanged.

The Linux SDK excludes GetTitleName under _XBOX. Thus Think is slot 30 and
SteamAPIActivated slot 36, not 37. Verified against supplied csgo/server.so:
GNU build ID 1db8361a2cad3f6ff19aaa54a453b16f1cd1351e; the ServerGameDLL005
registration constructor references factory RVA 0x6fe540; it returns object
0x1786088. The constructor installs vtable address 0x11f6678. Its slot 30 is
0x700500 (Think); slot 36 is 0x6ffe40 (Steam activation, true branch populates
Steam interfaces, false branch clears them); slot 37 is ApplyGameSettings,
which must not be hooked with a bool signature.

Compiled emulation now models late Steam activation without ANY GameFrame,
executes both generated SourceHook managers to verify slots 30/36, invokes their
actual delegates, tests false activation and Think fallback, absent accessors,
null game-server interfaces and partial hook setup cleanup. The production ELF
is checked for absence of the maps inventory pathname. This still does not
execute glibc or a live SourceHook/SRCDS runtime; a Linux server test is required.

## Native auth lock + SYNC_CORE (0.4.0)

See the current section at the top of RACE_REVIEW.md. The old RT stop-the-world
protocol is removed, including thread_quiescence.h. A live blocked-signal mask
made that protocol unusable for the supplied SRCDS environment. Three auth
CALLs now change under the exact native mutex identified above, with complete
caller-body verification and Linux SYNC_CORE before releasing it. No process
maps/task enumeration or signal delivery remains in the production library.

Callback observation uses the public Steam API registration mechanism.
License-query redirection is no longer installed: its caller lacks the proven
mutex. The old License policy helper remains research-only. profile.json lists
license/callback as unpatched_sites, preserving their reverse-engineered RVAs.
The build ID/profile checks and native authentication/callback results are not
bypassed. Kernel/glibc/SRCDS runtime testing is still outstanding.

## Temporary bridge console command (0.4.1)

Source contracts: hl2sdk/csgo/public/tier1/convar.h (ConCommandBase/ConCommand,
CCommand), public/icvar.h and appframework/IAppSystem.h, public/eiface.h.
The minimal i386 console adapter preserves command base size 24, derived size
36, Dispatch slot 15, argument size 1288 and argv array offset 1032. Commands
register through the official Metamod API with a unique ICvar DLL identifier.
ClientCommand pre-hook slot 6 on ServerGameClients004 mirrors Metamod's own
meta client command path; player output uses ClientConPrintf. Engine identity
comes from IVEngineServer023 GetClientSteamID slot 129, never a client convar.

Successful RegisterHook publishes a route label (archive/native) in a fixed
512-entry table; EndHook removes it. Duplicates/errors leave the label alone.
A short acquire/release spin lock covers label data only, with no external
calls while held; command output happens after releasing it. Auth's native
mutex may precede this label lock, but the command never acquires the native
mutex, so no reverse lock order is introduced. No label participates in
identity acceptance or duplicate-session decisions. Active unload is still
refused; pending unload/load failure unregisters the command and client hook.

Tests execute the compiled command vtable, its client SourceHook delegate and
manager, exact UTF-8 two-line replies, independent caller IDs, duplicate route
preservation and End cleanup. ELF init_array now runs in the emulator, matching
normal loader construction. Real-thread label insertion/read/removal is also
included in concurrency_tests.cpp. No live 0.4.1 command execution is claimed.
The supplied ServerGameClients004 factory RVA 0x6fe660 returns object 0x16eb278,
whose vtable is 0x11f67a8. Slot 6 points to 0x6ff6d0, which receives edict* and
CCommand&. This independently confirms the client command slot against the
provided server binary, in addition to the public SDK declaration.

## Server roster and copyright footer (0.4.2)

Server console/RCON bridge output now prints the version, connected-player
rows and a single copyright footer. Each row contains SDK player name, xuid
as SteamID64 and either bypass or proxied through bridge. Enumeration calls
IVEngineServer023 GetPlayerInfo slot 108 for slots 1..255 (the SDK absolute
player limit). Only the fixed SDK version/xuid/name prefix is consumed; the
output buffer reserves 512 bytes for the complete native SDK structure and
its alignment/padding. Failed/missing slots are skipped rather than ending
the scan. Names are terminated and control bytes become spaces so they cannot
create extra console rows; formatting always uses a fixed format string.

Client command replies retain their existing route wording. All copyright
strings now have the additional separator before the URL. Compiled emulator
coverage checks empty/nonempty rosters, sparse/high player slots, untrusted
names including percent/control bytes, bounded names, EndAuthSession cleanup,
absence of disconnected players and exactly one footer at the end. Existing
native-auth/duplicate/bootstrap regression checks also pass. The roster has
not been executed on a live SRCDS in the build environment.

## Compact SteamID32 server roster (0.4.3)

Server/RCON rows now use: # USERNAME  STEAM_U:X:Y bridge|steam.
SteamID32 here means the traditional Steam2 text representation, matching the
server's STEAM_1:X:Y logs. The universe is the top 8 SteamID64 bits, account ID
is the low 32 bits, X is its low bit and Y is account ID shifted right once.
Route labels still look up the complete SteamID64; formatting does not change
auth identity or duplicate-session handling. Tests cover both account parities,
exact labels/spacing, sparse slots and the common footer. Existing client
reply wording is preserved, with the new version number.

The user reported all four live checks passing before this formatting change:
cross-AppId duplicates, reconnect/map changes, plugin data identity and console
commands. This report is distinct from the build environment's emulator tests.
No new license-query compatibility is planned for this user's setup; the
original Steam ticket validation remains active.

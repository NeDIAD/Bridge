# Bridge

**Proper fix for archived CS:GO, with compatibility layer.**

Bridge is a Metamod:Source plugin for Linux i386 CS:GO servers. It allows archived
clients using AppId `4465480` to authenticate on a server using AppId `730`,
preserving the player's real SteamID and Steam's original authentication response.

## How it works

The native ticket verifier first checks the ticket for AppId `730`. Only when it
returns `GameMismatch` does Bridge retry the same native verification for AppId
`4465480`. After the engine's identity checks pass, the session is registered with
the matching AppId and awaits Steam validation.

Before registration, Bridge checks Steamclient's native session list for the same
SteamID under the other AppId. The check and registration run under the same native
mutex, so switching AppIds cannot create two simultaneous sessions for one account.
A duplicate returns `k_EBeginAuthSessionResultDuplicateRequest` (`2`), preserving
the first session. Duplicates within the same AppId retain the native result.
`EndAuthSession` cleans up both supported AppIds so the account can reconnect.

Bridge patches three calls in process memory; server files on disk remain unchanged.
It checks the supported binary build IDs and original instructions before installing
the hooks, using the native auth mutex and `SYNC_CORE` for synchronization. Steam's
callback is observed without changing its result. License queries remain unchanged.

## Authentication flow

```text
Client sends ticket + claimed SteamID
    ↓
Native ticket check for AppId 730
    ├─ OK → select AppId 730
    ├─ GameMismatch → retry native check for AppId 4465480
    │                    ├─ OK → select AppId 4465480
    │                    └─ Failure → reject
    └─ Other failure → reject with original result

After successful ticket verification:
    ↓
Engine checks ticket identity + account type
    ├─ Failure → reject
    └─ Pass
         ↓
Same SteamID already has a session under the other AppId?
    ├─ Yes → DuplicateRequest (2) → keep the first session
    └─ No
         ↓
Native session registration with the selected AppId
    ├─ Failure / same-AppId duplicate → return native result
    └─ Success
         ↓
Session pending Steam validation
         ↓
Steam → ValidateAuthTicketResponse → engine
    ├─ OK → real SteamID validated
    └─ Rejected → original rejection preserved
```

Successful local verification and registration are followed by a separate Steam
validation response. Bridge does not turn a rejection or a missing response into
successful authentication.

## Commands

Run `bridge` in the server console or through RCON to list connected players:

```text
Bridge 0.4.3
# ArchivedPlayer  STEAM_1:0:26039975 bridge
# DefaultPlayer  STEAM_1:1:26039975 steam
© Copyright 2026 NeDIAD | GNU/GPL-3.0 License | github.com/NeDIAD/Bridge
```

Each row uses `# USERNAME  STEAMID32 bridge/steam`. `bridge` identifies the archived
AppId route; `steam` identifies the default route. SteamID32 is displayed in Steam2
format (`STEAM_1:X:Y`). These labels describe the route, not the Steam validation result.

In a player's console, `bridge` replies only to that player. An archived connection
receives:

```text
You are connected via Bridge 0.4.3
© Copyright 2026 NeDIAD | GNU/GPL-3.0 License | github.com/NeDIAD/Bridge
```

A default connection receives:

```text
You are bypassing Bridge 0.4.3
© Copyright 2026 NeDIAD | GNU/GPL-3.0 License | github.com/NeDIAD/Bridge
```

## Verify that Bridge is working

1. With SRCDS stopped, copy the built `dist/addons/` contents into `csgo/addons/`.
   Remove conflicting auth patches and start the server. Updates require a full
   process restart; hot loading and unloading an active Bridge are unsupported.
2. Run `meta list`, find Bridge's plugin number, then run `meta info <number>`
   (for example, `meta info 1`). The plugin must report `running`. Check the startup
   log for:

   ```text
   [Bridge] Bridge 0.4.3 installed
   ```

   `waiting for modules` or `waiting for host Steam activation` means installation
   is still pending. A Bridge entry in `meta list` alone does not confirm installed hooks.
3. Connect an archived client and run `bridge` to check its route. Confirm that the
   server subsequently logs a successful Steam response for that player's SteamID64:

   ```text
   [Bridge] archive session started: steamid=76561198012345678 appid=4465480; awaiting Steam validation
   [Bridge] Steam ValidateAuthTicketResponse: steamid=76561198012345678 response=0 owner=76561198012345678 (OK)
   ```

   These are example IDs. The engine should also report `STEAM USERID validated`.
   The `awaiting Steam validation` line alone does not confirm successful authentication.
4. Check duplicate protection with the same account: connect through `4465480`,
   then attempt a simultaneous connection through `730`. Repeat in the opposite
   order. The second attempt must return `DuplicateRequest` (`2`), and the first
   session must remain connected. After disconnecting the first session, reconnecting
   should succeed. The duplicate log is:

   ```text
   [Bridge] duplicate auth session: steamid=76561198012345678 result=2 (DuplicateRequest)
   ```

Bridge supports the binary builds pinned in `src/profile.h` and
`src/native_lock_profile.h`. An incompatible build or conflicting patch prevents
installation. Runtime synchronization requires Linux support for
`MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` and a system policy that permits it.
If installation fails, check `meta info <number>` and the full `[Bridge]` startup log.

## Building

Requires Python **3.10+** and Zig **0.15.2**. Run the following commands from
the repository root on Windows or Linux to build the plugin for Linux i386.

Linux:

```sh
python3 tools/build.py --zig /path/to/zig
```

Windows PowerShell:

```powershell
python tools/build.py --zig "C:\path\to\zig.exe"
```

If Zig is in your `PATH`, you can omit the `--zig` option.

Build output:

```text
dist/addons/bridge/bin/bridge_mm_i486.so
dist/addons/metamod/bridge.vdf
```

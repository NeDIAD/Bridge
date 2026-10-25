"""Run the compiled Metamod plugin's loader and hooks on an emulated i386 CPU.

Linux loader/libc services and Steam replies are mocked. This is not a Steam
backend test. Original engine and Steamclient files are only read.
"""
import json
from pathlib import Path
import struct
from fixture_support import fixture_directory, read_fixture

ROOT = Path(__file__).resolve().parent.parent
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.x86_const import *


class Machine:
    EXT, STEAM, ENGINE = 0x10000000, 0x20000000, 0x30000000
    HEAP, TLS, STUBS, STACK = 0x60000000, 0x60100000, 0x50000000, 0x70000000

    def __init__(self, old_bypass=False, bad_build=False, fail_write=False, missing_steam=False,
                 blocked_peer=False, fail_rx=False, cooperative_peer=False, isolated_steam=False,
                 engine_alias=False, api_ready=True, wrong_namespace_base=False,
                 api_symbol=True, server_api_exports=True, interface_ready=True, fail_activation=False,
                 busy_mutex=False, fail_barrier=False, fail_sync_after_write=False, bad_lock=False):
        self.busy_mutex = busy_mutex
        self.fail_barrier = fail_barrier
        self.fail_sync_after_write = fail_sync_after_write
        self.native_lock_held = False
        self.barriers = []
        self.observer = 0
        self.observer_registrations = 0
        self.console_command = 0
        self.console_output, self.client_output, self.meta_results = [], [], []
        self.client_identities = {}
        self.unregistered_commands = []
        self.client_args = None
        self.roster = {}
        self.player_info_queries = []
        self.cpu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.pages = set()
        self.handlers = {}
        self.heap = self.HEAP
        self.protection_calls = []
        self.fail_write = fail_write
        self.failed_once = False
        self.fail_rx = fail_rx
        self.rx_failed = False
        self.signals = {}
        self.ticket_traces = []
        self.log_formats = []
        self.isolated_steam = isolated_steam
        self.steam_api_ready = api_ready and not missing_steam
        self.wrong_namespace_base = wrong_namespace_base
        self.namespace_probes = []
        self.api_symbol = api_symbol
        self.server_api_exports = server_api_exports
        self.interface_ready = interface_ready
        self.fail_activation = fail_activation
        self.kernel_tasks = [101, 202] if blocked_peer or cooperative_peer else [101]
        self.cooperative_peer = cooperative_peer
        self.current_tid = 101
        self.owner_context = None
        self.peer_context = None
        self.peer_wait = 0
        self.peer_parked = False
        self.handler_returns = 0
        self.kernel_clock = 0
        self.directory_done = False
        self.queued_signals = []
        self.map(self.HEAP, 0x200000)
        self.map(self.STACK, 0x100000)
        self.map(self.STUBS, 0x10000)
        self.sentinel = self.STUBS
        self.continuation = self.STUBS + 0x10
        self.signal_return = self.STUBS + 0x20
        self.symbols = {}
        self.stub_next = self.STUBS + 0x100
        self.cpu.hook_add(UC_HOOK_CODE, self.dispatch)
        self.cpu.hook_add(UC_HOOK_INTR, self.interrupt)
        self.profile = json.loads((ROOT / 'analysis/profile.json').read_text())
        self.engine = FIXTURE_BYTES['engine']
        self.steam = FIXTURE_BYTES['steamclient']
        for base, data, offsets in [
            (self.ENGINE, self.engine, [0, 0x18a2ba, 0x501b64]),
            (self.STEAM, self.steam, [0] + [int(x['rva'], 16) for x in self.profile['sites'] + self.profile.get('unpatched_sites', [])])]:
            for offset in offsets:
                page = offset & ~4095
                self.map(base + page, 4096)
                self.cpu.mem_write(base + page, data[page:page + 4096])
        self.put32(self.ENGINE + 0x18a2bd, self.ENGINE + 0x501b64)
        for i in range(6):
            original = struct.unpack_from('<I', self.engine, 0x501b64 + i * 4)[0]
            self.put32(self.ENGINE + 0x501b64 + i * 4, self.ENGINE + original)
        if old_bypass:
            self.put32(self.ENGINE + 0x501b64 + 16, self.ENGINE + 0x18a498)
        if bad_build:
            self.cpu.mem_write(self.STEAM + 0x164, b'BAD!')
        if bad_lock:
            self.put32(self.STEAM + 0x489105, 0x2f91c)
        self.infos = []
        engine_name = b'/srv/bin/engine_srv.so' if engine_alias else b'/srv/bin/engine.so'
        for base, data, name in [(self.ENGINE, self.engine, engine_name),
                                 (self.STEAM, self.steam, b'/srv/bin/steamclient.so')]:
            phoff = struct.unpack_from('<I', data, 28)[0]
            phnum = struct.unpack_from('<H', data, 44)[0]
            name_addr = self.alloc(name + b'\0')
            self.infos.append(self.alloc(struct.pack('<IIIH2x', base, name_addr, base + phoff, phnum)))
        self.all_infos = self.infos.copy()
        if missing_steam:
            self.infos = self.infos[:1]
        if True: # The host API module exists even before its user initializes.
            api_base = 0x40000000
            self.map(api_base, 4096)
            self.cpu.mem_write(api_base, self.steam[:4096])
            phoff = struct.unpack_from('<I', self.steam, 28)[0]
            phnum = struct.unpack_from('<H', self.steam, 44)[0]
            api_info = self.alloc(struct.pack('<IIIH2x', api_base,
                self.alloc(b'/srv/bin/libsteam_api.so\0'), api_base + phoff, phnum))
            self.all_infos.append(api_info)
            if isolated_steam or missing_steam:
                self.infos = [self.infos[0], api_info]
            else:
                self.infos.append(api_info)
            vtable = self.alloc(struct.pack('<I', self.STEAM + 0x1f3360))
            self.steam_client = self.alloc(struct.pack('<I', vtable))
        self.listener = 0
        self.bootstrap_args = None
        self.activation_args = None
        self.removed_hooks = []
        self.make_metamod_api()
        self.load_plugin()
        self.api_object = self.call(self.symbols['CreateInterface'], self.alloc(b'ISmmPlugin\0'), 0)
        self.vtable = self.get32(self.api_object)

    def map(self, address, size):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            if page not in self.pages:
                self.cpu.mem_map(page, 4096)
                self.pages.add(page)

    def alloc(self, data):
        address = self.heap
        self.heap += (len(data) + 15) & ~15
        self.cpu.mem_write(address, bytes(data))
        return address

    def get32(self, address):
        return struct.unpack('<I', self.cpu.mem_read(address, 4))[0]

    def put32(self, address, value):
        self.cpu.mem_write(address, struct.pack('<I', value & 0xffffffff))

    def string(self, address):
        result = bytearray()
        while address and len(result) < 8192:
            value = self.cpu.mem_read(address, 1)[0]
            if not value:
                break
            result.append(value)
            address += 1
        return bytes(result)

    def args(self, count):
        sp = self.cpu.reg_read(UC_X86_REG_ESP)
        return [self.get32(sp + 4 + i * 4) for i in range(count)]

    def ret(self, value=0):
        sp = self.cpu.reg_read(UC_X86_REG_ESP)
        self.cpu.reg_write(UC_X86_REG_EAX, value & 0xffffffff)
        self.cpu.reg_write(UC_X86_REG_EIP, self.get32(sp))
        self.cpu.reg_write(UC_X86_REG_ESP, sp + 4)

    def dispatch(self, cpu, address, _size, _context):
        if address == self.sentinel:
            cpu.emu_stop()
        elif address == self.signal_return:
            self.handler_returns += 1
            self.peer_parked = False
            cpu.context_restore(self.owner_context)
            cpu.reg_write(UC_X86_REG_EIP, cpu.reg_read(UC_X86_REG_EIP))
            self.current_tid = 101
            self.owner_context = None
            self.peer_context = None
        elif address == self.continuation:
            self.next_module()
        elif address in self.handlers:
            self.handlers[address]()

    def interrupt(self, cpu, number, _context):
        assert number == 0x80
        syscall = cpu.reg_read(UC_X86_REG_EAX)
        a, b, c, d = [cpu.reg_read(reg) for reg in [UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI]]
        result = 0
        if syscall == 375: # membarrier, independent of signal masks
            self.barriers.append(a)
            if self.fail_barrier:
                result = -38
            elif a == 0:
                result = 32 | 64
            elif a in (32, 64):
                if a == 32 and self.protection_calls:
                    assert self.native_lock_held
                    if self.fail_sync_after_write:
                        result = -1
            else:
                raise AssertionError(f'unknown membarrier operation {a}')
        elif syscall == 162: # nanosleep while waiting for the native mutex
            result = 0
        elif syscall == 20: # getpid
            result = 100
        elif syscall == 224: # gettid
            result = self.current_tid
        elif syscall == 265: # clock_gettime
            self.kernel_clock += 50
            cpu.mem_write(b, struct.pack('<II', self.kernel_clock // 1000, self.kernel_clock % 1000 * 1000000))
        elif syscall == 5: # open /proc/self/task
            assert self.string(a) == b'/proc/self/task'
            self.directory_done = False
            result = 42
        elif syscall == 220: # getdents64
            assert a == 42
            data = bytearray()
            if not self.directory_done:
                for tid in self.kernel_tasks:
                    name = str(tid).encode() + b'\0'
                    length = (19 + len(name) + 7) & ~7
                    entry = struct.pack('<QQHB', tid, 0, length, 4) + name
                    data.extend(entry.ljust(length, b'\0'))
            self.directory_done = True
            if data:
                cpu.mem_write(b, bytes(data))
            result = len(data)
        elif syscall == 335: # rt_tgsigqueueinfo: blocked peer intentionally does not ack
            assert a == 100 and b in self.kernel_tasks and c == 64
            info = bytes(cpu.mem_read(d, 128))
            self.queued_signals.append((a, b, c, info))
            if self.cooperative_peer:
                cpu.reg_write(UC_X86_REG_EAX, 0)
                self.owner_context = cpu.context_save()
                self.current_tid = b
                info_address = self.alloc(info)
                sp = self.STACK + 0x7f000
                cpu.mem_write(sp, struct.pack('<IIII', self.signal_return, c, info_address, 0))
                cpu.reg_write(UC_X86_REG_ESP, sp)
                cpu.reg_write(UC_X86_REG_EBP, 0)
                cpu.reg_write(UC_X86_REG_EIP, struct.unpack_from('<I', self.signals[c])[0])
                return
        elif syscall == 240: # futex: execute actual peer handler park/resume paths
            if self.cooperative_peer and self.current_tid == 202 and b == 128 and self.get32(a) == c:
                cpu.reg_write(UC_X86_REG_EAX, 0)
                self.peer_context = cpu.context_save()
                self.peer_wait = a
                self.peer_parked = True
                cpu.context_restore(self.owner_context)
                cpu.reg_write(UC_X86_REG_EIP, cpu.reg_read(UC_X86_REG_EIP))
                self.current_tid = 101
                return
            if self.cooperative_peer and self.current_tid == 101 and b == 129 and a == self.peer_wait and self.get32(a) == 0:
                cpu.reg_write(UC_X86_REG_EAX, 1)
                self.owner_context = cpu.context_save()
                cpu.context_restore(self.peer_context)
                cpu.reg_write(UC_X86_REG_EIP, cpu.reg_read(UC_X86_REG_EIP))
                self.current_tid = 202
                return
            result = 0
        elif syscall == 6: # close
            result = 0
        else:
            raise AssertionError(f'unexpected raw Linux syscall {syscall}')
        cpu.reg_write(UC_X86_REG_EAX, result & 0xffffffff)

    def next_module(self):
        if not self.iter_infos:
            self.cpu.reg_write(UC_X86_REG_ESP, self.iter_sp)
            self.ret(0)
            return
        info = self.iter_infos.pop(0)
        sp = self.iter_sp - 16
        self.cpu.mem_write(sp, struct.pack('<IIII', self.continuation, info, 16, self.iter_context))
        self.cpu.reg_write(UC_X86_REG_ESP, sp)
        self.cpu.reg_write(UC_X86_REG_EIP, self.iter_callback)

    def external(self, name):
        if name == 'stderr':
            return self.alloc(struct.pack('<I', 2))
        address = self.stub_next
        self.stub_next += 16
        self.cpu.mem_write(address, b'\xc3')

        def handler():
            if name == 'dl_iterate_phdr':
                self.iter_callback, self.iter_context = self.args(2)
                self.iter_sp = self.cpu.reg_read(UC_X86_REG_ESP)
                self.iter_infos = self.infos.copy()
                self.next_module()
            elif name == 'sigaction':
                signal, action, old = self.args(3)
                if old:
                    self.cpu.mem_write(old, self.signals.get(signal, bytes(140)))
                if action:
                    self.signals[signal] = bytes(self.cpu.mem_read(action, 140))
                self.ret(0)
            elif name == 'sigfillset':
                self.cpu.mem_write(self.args(1)[0], bytes([255]) * 128)
                self.ret(0)
            elif name == '__libc_current_sigrtmax':
                self.ret(64)
            elif name == '__libc_current_sigrtmin':
                self.ret(34)
            elif name == 'memset':
                dst, value, length = self.args(3)
                self.cpu.mem_write(dst, bytes([value & 255]) * length)
                self.ret(dst)
            elif name == 'malloc':
                self.ret(self.alloc(bytes(self.args(1)[0])))
            elif name == 'free':
                self.ret()
            elif name == 'abort':
                raise AssertionError('compiled plugin called abort')
            elif name == 'mm_MetaFactory':
                assert self.string(self.args(4)[1]) == b'ISourceHook'
                self.ret(self.sourcehook_api)
            elif name == 'mm_GetServerFactory':
                self.ret(self.server_factory)
            elif name == 'mm_GetEngineFactory':
                self.ret(self.engine_factory)
            elif name == 'mm_EngineFactory':
                interface_name = self.string(self.args(2)[0])
                assert interface_name in (b'VEngineServer023', b'VEngineCvar007')
                self.ret(self.engine_api if interface_name == b'VEngineServer023' else self.cvar_api)
            elif name == 'cvar_FindCommandBase':
                assert self.string(self.args(2)[1]) == b'bridge'
                self.ret(0)
            elif name == 'cvar_AllocateDLLIdentifier':
                self.ret(57)
            elif name == 'mm_RegisterCommand':
                _, _, command = self.args(3)
                assert self.string(self.get32(command + 12)) == b'bridge'
                assert self.get32(command + 20) == 0
                assert self.cpu.mem_read(command + 32, 1)[0] & 2
                self.console_command = command
                self.cpu.mem_write(command + 8, b'\x01')
                self.ret(1)
            elif name == 'mm_UnregisterCommand':
                command = self.args(3)[2]
                assert command == self.console_command
                self.unregistered_commands.append(command)
                self.ret(0)
            elif name == 'mm_ConPrint':
                self.console_output.append(self.string(self.args(2)[1]))
                self.ret(0)
            elif name == 'mm_ConPrintf':
                _, fmt, username, universe, parity, account, route = self.args(7)
                assert self.string(fmt) == b'# %s  STEAM_%u:%u:%u %s\n'
                steamid = f'STEAM_{universe}:{parity}:{account}'.encode()
                self.console_output.append(b'# ' + self.string(username) + b'  ' + steamid
                    + b' ' + self.string(route) + b'\n')
                self.ret(0)
            elif name == 'mm_ClientConPrintf':
                _, client, fmt, message = self.args(4)
                assert self.string(fmt) == b'%s'
                self.client_output.append((client, self.string(message)))
                self.ret(0)
            elif name == 'engine_GetClientSteamID':
                _, client, validated = self.args(3)
                assert validated == 0
                peer = self.client_identities.get(client, 0)
                self.ret(self.alloc(struct.pack('<Q', peer)) if peer else 0)
            elif name == 'engine_GetPlayerInfo':
                _, slot, out = self.args(3)
                assert 1 <= slot <= 255
                self.player_info_queries.append(slot)
                if slot not in self.roster:
                    self.ret(0)
                else:
                    peer, username = self.roster[slot]
                    data = bytearray(512)
                    struct.pack_into('<QQ', data, 0, 1, peer)
                    data[16:16 + min(128, len(username))] = username[:128]
                    self.cpu.mem_write(out, bytes(data))
                    self.ret(1)
            elif name == '__cxa_atexit':
                self.ret(0)
            elif name == 'mm_AddListener':
                self.listener = self.args(3)[2]
                self.ret()
            elif name == 'mm_ServerFactory':
                interface_name = self.string(self.args(2)[0])
                assert interface_name in (b'ServerGameDLL005', b'ServerGameClients004')
                self.ret(self.server_dll if interface_name == b'ServerGameDLL005' else self.game_clients)
            elif name == 'sh_Version':
                self.ret(5)
            elif name == 'sh_AddHook':
                if self.client_args is None:
                    self.client_args = self.args(8)
                    self.ret(75)
                elif self.bootstrap_args is None:
                    self.bootstrap_args = self.args(8)
                    self.ret(73)
                else:
                    self.activation_args = self.args(8)
                    self.ret(0 if self.fail_activation else 74)
            elif name == 'sh_RemoveHookByID':
                self.removed_hooks.append(self.args(2)[1])
                self.ret(1)
            elif name == 'sh_SetRes':
                self.meta_results.append(self.args(2)[1])
                self.ret()
            elif name == 'sh_SetInfo':
                self.hook_info = self.args(6)
                self.ret()
            elif name == 'memcpy':
                dst, src, length = self.args(3)
                self.cpu.mem_write(dst, bytes(self.cpu.mem_read(src, length)))
                self.ret(dst)
            elif name in ('memcmp', 'bcmp'):
                left, right, length = self.args(3)
                a, b = bytes(self.cpu.mem_read(left, length)), bytes(self.cpu.mem_read(right, length))
                self.ret((a > b) - (a < b))
            elif name == 'strcmp':
                a, b = (self.string(p) for p in self.args(2))
                self.ret((a > b) - (a < b))
            elif name == 'strrchr':
                source, char = self.args(2)
                index = self.string(source).rfind(bytes([char]))
                self.ret(source + index if index >= 0 else 0)
            elif name in ('snprintf', 'vsnprintf'):
                dst, length = self.args(2)
                if name == 'vsnprintf':
                    fmt, values = self.args(4)[2:4]
                    message = self.string(fmt)
                    self.log_formats.append(message)
                    if message.startswith(b'ticket check:'):
                        self.ticket_traces.append(struct.unpack('<QQiiii', self.cpu.mem_read(values, 32)))
                if length:
                    self.cpu.mem_write(dst, b'\0')
                self.ret(0)
            elif name == 'fprintf':
                self.ret(0)
            elif name == 'dladdr':
                address, out = self.args(2)
                native = self.STEAM <= address < self.STEAM + 0x3000000
                filename = self.alloc(b'/srv/bin/steamclient.so\0' if native else
                                      b'/srv/addons/bridge/bin/bridge_mm_i486.so\0')
                self.cpu.mem_write(out, struct.pack('<IIII', filename, self.STEAM if native else self.EXT, 0, 0))
                self.ret(1)
            elif name == 'dlopen':
                self.ret(1)
            elif name == 'dlsym':
                _, symbol = self.args(2)
                symbol = self.string(symbol)
                if symbol == b'SteamGameServer_GetHSteamUser':
                    self.ret(self.external('steam_GetUser') if self.server_api_exports else 0)
                elif symbol == b'SteamAPI_RegisterCallback':
                    self.ret(self.external('steam_RegisterCallback'))
                elif symbol in (b'pthread_mutex_trylock', b'pthread_mutex_unlock'):
                    assert self.args(2)[0] == 0xabc0 # Pinned native namespace handle.
                    self.ret(self.external(symbol.decode()))
                elif symbol == b'SteamInternal_FindOrCreateGameServerInterface':
                    self.ret(self.external('steam_FindGameInterface') if self.server_api_exports else 0)
                else:
                    assert symbol == b'SteamInternal_CreateInterface'
                    self.ret(self.external('steam_CreateInterface') if self.api_symbol else 0)
            elif name == 'steam_RegisterCallback':
                callback, kind = self.args(2)
                assert kind == 143 and not self.native_lock_held
                assert self.cpu.mem_read(callback + 4, 1)[0] == 2
                self.observer = callback
                self.observer_registrations += 1
                self.ret()
            elif name == 'pthread_mutex_trylock':
                assert self.args(1)[0] == self.STEAM + 0x22ec278
                assert not self.native_lock_held
                if self.busy_mutex:
                    self.ret(16)
                else:
                    self.native_lock_held = True
                    self.ret(0)
            elif name == 'pthread_mutex_unlock':
                assert self.args(1)[0] == self.STEAM + 0x22ec278 and self.native_lock_held
                self.native_lock_held = False
                self.ret(0)
            elif name == 'steam_GetUser':
                self.ret(1 if self.steam_api_ready else 0)
            elif name == 'steam_FindGameInterface':
                user, version = self.args(2)
                assert user == 1 and self.string(version) == b'SteamGameServer014'
                self.ret(self.steam_client if self.interface_ready else 0)
            elif name == 'steam_CreateInterface':
                assert self.string(self.args(1)[0]) == b'SteamClient020'
                self.ret(self.steam_client if self.steam_api_ready else 0)
            elif name == 'dlmopen':
                ns, path, flags = self.args(3)
                assert self.string(path) == b'/srv/bin/steamclient.so'
                assert flags & 4 and flags & 0x1000 # NOLOAD + NODELETE
                self.namespace_probes.append(ns)
                self.ret(0xabc0 if ns == 3 else 0)
            elif name == 'dlinfo':
                handle, request, out = self.args(3)
                assert handle == 0xabc0 and request == 2 # RTLD_DI_LINKMAP
                base = self.STEAM + 4096 if self.wrong_namespace_base else self.STEAM
                self.put32(out, self.alloc(struct.pack('<IIIII', base, 0, 0, 0, 0)))
                self.ret(0)
            elif name == 'dlclose':
                self.ret(0)
            elif name == 'sysconf':
                self.ret(4096)
            elif name == 'mprotect':
                args = self.args(3)
                self.protection_calls.append(args)
                assert self.native_lock_held, 'text changes outside the native mutex'
                if self.fail_write and args[2] == 7:
                    self.failed_once = True
                    self.ret(-1)
                elif self.fail_rx and args[2] == 5 and not self.rx_failed:
                    self.rx_failed = True
                    self.ret(-1)
                else:
                    self.ret(0)
            elif name == '___tls_get_addr':
                index = self.cpu.reg_read(UC_X86_REG_EAX) # i386 regparm(1)
                self.ret(self.TLS + (0x1000 if self.current_tid == 202 else 0) + self.get32(index + 4))
            else:
                raise AssertionError(f'unexpected import {name}')
        self.handlers[address] = handler
        return address

    def make_metamod_api(self):
        def table(names):
            methods = [self.external(name) for name in names]
            vtable = self.alloc(struct.pack('<' + 'I' * len(methods), *methods))
            return self.alloc(struct.pack('<I', vtable))
        names = ['sh_Unexpected'] * 24
        names[0] = names[1] = 'sh_Version'
        names[2], names[4], names[7] = 'sh_AddHook', 'sh_RemoveHookByID', 'sh_SetRes'
        self.sourcehook_api = table(names)
        names = ['mm_Unexpected'] * 30
        names[4], names[12], names[13] = 'mm_GetServerFactory', 'mm_AddListener', 'mm_MetaFactory'
        names[1], names[6], names[7] = 'mm_GetEngineFactory', 'mm_RegisterCommand', 'mm_UnregisterCommand'
        names[8], names[9], names[18] = 'mm_ConPrint', 'mm_ConPrintf', 'mm_ClientConPrintf'
        self.mm_api = table(names)
        self.server_factory = self.external('mm_ServerFactory')
        self.server_dll = self.alloc(bytes(24))
        self.game_clients = self.alloc(bytes(24))
        self.engine_factory = self.external('mm_EngineFactory')
        names = ['engine_Unexpected'] * 130
        names[108] = 'engine_GetPlayerInfo'
        names[129] = 'engine_GetClientSteamID'
        self.engine_api = table(names)
        names = ['cvar_Unexpected'] * 15
        names[9], names[14] = 'cvar_AllocateDLLIdentifier', 'cvar_FindCommandBase'
        self.cvar_api = table(names)

    def load(self, late=0):
        self.error = self.alloc(bytes(256))
        return self.method(3, 1, self.mm_api, self.error, 256, late)

    def load_plugin(self):
        with (ROOT / 'dist/addons/bridge/bin/bridge_mm_i486.so').open('rb') as stream:
            elf = ELFFile(stream)
            assert elf.elfclass == 32 and elf['e_machine'] == 'EM_386'
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    self.map(self.EXT + segment['p_vaddr'], segment['p_memsz'])
                    self.cpu.mem_write(self.EXT + segment['p_vaddr'], segment.data())
            symbols = elf.get_section_by_name('.dynsym')
            externals = {}
            for symbol in symbols.iter_symbols():
                if symbol['st_shndx'] != 'SHN_UNDEF':
                    self.symbols[symbol.name] = self.EXT + symbol['st_value']
            for section in elf.iter_sections():
                if section['sh_type'] != 'SHT_REL':
                    continue
                for rel in section.iter_relocations():
                    address = self.EXT + rel['r_offset']
                    kind = rel['r_info_type']
                    if kind == 8: # R_386_RELATIVE
                        self.put32(address, self.get32(address) + self.EXT)
                    elif kind == 35: # R_386_TLS_DTPMOD32
                        self.put32(address, 1)
                    elif kind in (6, 7): # GLOB_DAT, JMP_SLOT
                        name = symbols.get_symbol(rel['r_info_sym']).name
                        if name not in externals:
                            externals[name] = self.external(name)
                        self.put32(address, externals[name])
                    else:
                        raise AssertionError(f'unhandled relocation {kind}')
            initializers = elf.get_section_by_name('.init_array')
            if initializers:
                for offset in range(0, initializers['sh_size'], 4):
                    self.call(self.get32(self.EXT + initializers['sh_addr'] + offset))

    def call(self, address, *args):
        sp = self.STACK + 0xff000 - (4 * (len(args) + 1) + 15 & ~15)
        self.cpu.mem_write(sp, struct.pack('<' + 'I' * (len(args) + 1), self.sentinel, *args))
        self.cpu.reg_write(UC_X86_REG_ESP, sp)
        self.cpu.emu_start(address, 0, count=20_000_000)
        assert self.cpu.reg_read(UC_X86_REG_EIP) == self.sentinel, 'instruction budget exhausted'
        return self.cpu.reg_read(UC_X86_REG_EAX)

    def method(self, index, *args):
        result = self.call(self.get32(self.vtable + index * 4), self.api_object, *args)
        # Linux i386 bool return is AL; upper EAX bits are unspecified.
        return result & 255 if index in (3, 5, 6, 7, 8) else result

    def original_calls(self):
        for item in self.profile['sites']:
            rva = int(item['rva'], 16)
            assert bytes(self.cpu.mem_read(self.STEAM + rva, 5)).hex() == item['original_call']

    def native_stub(self, rva, handler):
        address = self.STEAM + rva
        self.map(address, 1)
        self.cpu.mem_write(address, b'\xc3')
        self.handlers[address] = handler


def run():
    production = (ROOT / 'dist/addons/bridge/bin/bridge_mm_i486.so').read_bytes()
    assert b'/proc/self/maps' not in production
    assert b'/proc/self/task' not in production
    with (ROOT / 'dist/addons/bridge/bin/bridge_mm_i486.so').open('rb') as stream:
        elf = ELFFile(stream)
        assert elf.elfclass == 32 and elf['e_type'] == 'ET_DYN' and elf['e_machine'] == 'EM_386'
        dynamic = list(elf.get_section_by_name('.dynamic').iter_tags())
        assert not any(tag.entry.d_tag == 'DT_TEXTREL' for tag in dynamic)
        needed = {tag.needed for tag in dynamic if tag.entry.d_tag == 'DT_NEEDED'}
        # Mutex operations resolve from the pinned native Steam namespace.
        assert needed == {'libc.so.6', 'libdl.so.2', 'ld-linux.so.2'}
        assert any(tag.entry.d_tag == 'DT_FLAGS' and tag.entry.d_val & 8 for tag in dynamic)
        assert any(seg['p_type'] == 'PT_GNU_RELRO' for seg in elf.iter_segments())
        assert all(not (seg['p_flags'] & 1) for seg in elf.iter_segments() if seg['p_type'] == 'PT_GNU_STACK')
        exports = {sym.name for sym in elf.get_section_by_name('.dynsym').iter_symbols()
                   if sym['st_shndx'] != 'SHN_UNDEF' and sym['st_info']['bind'] == 'STB_GLOBAL'}
        assert exports == {'CreateInterface'}
    print('PASS: ELF32, Metamod factory, runtime dependencies, RELRO/NOW, non-executable stack')
    m = Machine()
    assert m.method(0) == 16
    error = m.alloc(bytes(256))
    assert m.load() == 1
    hooks = {}
    for item in m.profile['sites']:
        site = m.STEAM + int(item['rva'], 16)
        call = bytes(m.cpu.mem_read(site, 5))
        assert call[0] == 0xe8
        target = (site + 5 + struct.unpack_from('<i', call, 1)[0]) & 0xffffffff
        assert m.EXT <= target < m.EXT + 0x10000
        hooks[item['name']] = target
    assert m.method(5, error, 256) == 1
    assert m.get32(m.ENGINE + 0x501b64 + 16) == m.ENGINE + 0x18a3d8
    assert len(m.protection_calls) == 2 and [x[2] for x in m.protection_calls] == [7, 5]
    for item in m.profile['unpatched_sites']:
        assert bytes(m.cpu.mem_read(m.STEAM + int(item['rva'], 16), 5)) == bytes.fromhex(item['original_call'])

    seen_games, registrations, ends, licenses, callbacks = [], [], [], [], []
    peer = 76561198012345678
    ticket_app = 4465480
    low, high = peer & 0xffffffff, peer >> 32

    def verify():
        _, game, _, _, offset, identity, claim_low, claim_high = m.args(8)
        app = m.get32(game)
        seen_games.append(app)
        m.put32(offset, 40)
        m.cpu.mem_write(identity, struct.pack('<Q', peer))
        m.ret(0 if app == ticket_app else 4)

    def register():
        args = m.args(10)
        app = m.get32(args[2])
        registrations.append((app, args[6], args[7]))
        ptr, count = m.get32(args[0] + 0x1700), m.get32(args[0] + 0x170c)
        for i in range(count):
            mode, _, existing_peer, existing_game = struct.unpack('<IIQQ', m.cpu.mem_read(ptr + i * 0x8c, 24))
            if mode & ~2 == 1 and existing_peer == (args[7] << 32 | args[6]) and existing_game == app:
                m.ret(2)
                return
        m.ret(0)

    def end():
        args = m.args(4)
        app = m.get32(args[3])
        ends.append(app)
        ptr, count = m.get32(args[0] + 0x1700), m.get32(args[0] + 0x170c)
        if count:
            mode, _, existing_peer, existing_game = struct.unpack('<IIQQ', m.cpu.mem_read(ptr, 24))
            if existing_peer == (args[2] << 32 | args[1]) and existing_game == app:
                m.put32(args[0] + 0x170c, 0)
        m.ret()

    def license():
        args = m.args(5)
        licenses.append((m.get32(args[3]), args[4]))
        m.ret(2 if m.get32(args[3]) == 730 else 1)

    def callback():
        args = m.args(4)
        callbacks.append((args[1], bytes(m.cpu.mem_read(args[2], args[3]))))
        m.ret()

    for rva, handler in [(0x1f3360, verify), (0x1f3810, register), (0x1f3f70, end),
                          (0x1f4120, license), (0x1f2960, callback)]:
        m.native_stub(rva, handler)
    server = m.alloc(bytes(0x1800))
    game = m.alloc(struct.pack('<Q', 730))
    ticket = m.alloc(bytes(100))
    offset = m.alloc(bytes(4))
    identity = m.alloc(bytes(8))
    handle = m.alloc(bytes(4))

    copyright = '\u00a9 Copyright 2026 NeDIAD | GNU/GPL-3.0 License | github.com/NeDIAD/Bridge\n'.encode()
    def command_args(token=b'bridge', extra=None):
        data = bytearray(1288)
        struct.pack_into('<I', data, 0, 2 if extra else 1)
        struct.pack_into('<I', data, 1032, m.alloc(token + b'\0'))
        if extra:
            struct.pack_into('<I', data, 1036, m.alloc(extra + b'\0'))
        return m.alloc(data)

    def client_command(remote=peer, token=b'bridge', extra=None):
        edict = 0x77700000
        m.client_identities[edict] = remote
        delegate = m.client_args[6]
        m.call(m.get32(m.get32(delegate) + 8), delegate, edict, command_args(token, extra))
        return m.client_output[-1][1] if m.client_output else None

    command_vtable = m.get32(m.console_command)
    assert m.string(m.call(m.get32(command_vtable + 7 * 4), m.console_command)) == b'bridge'
    assert m.call(m.get32(command_vtable + 10 * 4), m.console_command) == 57
    m.call(m.get32(command_vtable + 15 * 4), m.console_command, command_args())
    assert m.console_output == [b'Bridge 0.4.3\n', copyright]
    assert m.player_info_queries == list(range(1, 256))
    assert m.client_args[7] == 0 # ClientCommand pre-hook, matching Metamod's meta command path.
    info_vtable = m.alloc(struct.pack('<I', m.external('sh_SetInfo')))
    assert m.call(m.client_args[5], 0, m.alloc(struct.pack('<I', info_vtable))) == 0
    assert m.hook_info[1:4] == [1, 0, 6]
    assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
    assert seen_games == [730, 4465480]
    assert m.ticket_traces[-1] == (peer, 730, 4, 0, 0, 100)
    assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 0
    assert registrations == [(4465480, low, high)]
    def server_command():
        m.console_output.clear()
        m.call(m.get32(command_vtable + 15 * 4), m.console_command, command_args())
        return b''.join(m.console_output)

    m.roster = {1: (peer, b'NeDIAD'), 3: (peer + 1, b'Default %s\nPlayer\r\x1b'),
                255: (peer + 2, b'A' * 128)}
    roster = server_command()
    assert roster == (b'Bridge 0.4.3\n# NeDIAD  STEAM_1:0:26039975 bridge\n'
        + b'# Default %s Player    STEAM_1:1:26039975 steam\n'
        + b'# ' + b'A' * 127 + b'  STEAM_1:0:26039976 steam\n' + copyright)
    assert roster.count(copyright) == 1 and roster.endswith(copyright)
    del m.roster[1] # A stale route label cannot invent a player absent from engine enumeration.
    assert b'# NeDIAD  ' not in server_command()
    m.roster = {1: (peer, b'NeDIAD')}
    assert client_command() == b'You are connected via Bridge 0.4.3\n' + copyright
    assert m.meta_results[-1] == 3 # MRES_SUPERCEDE suppresses the unknown-command path.
    assert client_command(token=b'BRIDGE', extra=b'somebody_else') == b'You are connected via Bridge 0.4.3\n' + copyright
    before = len(m.client_output)
    client_command(token=b'bridge_other')
    assert len(m.client_output) == before and m.meta_results[-1] == 0
    assert client_command(remote=peer + 1) == b'You are bypassing Bridge 0.4.3\n' + copyright
    m.call(hooks['end'], server, low, high, game)
    assert ends == [730, 4465480]
    assert b'# NeDIAD  STEAM_1:0:26039975 steam\n' in server_command()
    m.roster.clear()
    assert server_command() == b'Bridge 0.4.3\n' + copyright
    assert client_command() == b'You are bypassing Bridge 0.4.3\n' + copyright
    ticket_app = 730
    assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
    assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 0
    assert client_command() == b'You are bypassing Bridge 0.4.3\n' + copyright
    m.call(hooks['end'], server, low, high, game)
    ticket_app = 4465480
    assert all(client == 0x77700000 for client, _ in m.client_output)
    print('PASS: bridge client reply/server roster ABI, SteamID32 routes, empty roster and single UTF-8 footer')
    assert m.observer_registrations == 1
    observer_vtable = m.get32(m.observer)
    assert m.call(m.get32(observer_vtable + 8), m.observer) == 20
    for response in [0, 1, 2, 6, 9]:
        payload = struct.pack('<QIQ', peer, response, peer)
        address = m.alloc(payload)
        m.call(m.get32(observer_vtable), m.observer, address)
        m.call(m.STEAM + 0x1f2960, server, 143, address, len(payload))
        assert callbacks[-1] == (143, payload)
        assert bytes(m.cpu.mem_read(address, 20)) == payload
    log_count = len(m.log_formats)
    m.call(m.get32(observer_vtable + 4), m.observer, address, 1, 123, 0)
    assert len(m.log_formats) == log_count # Failed call-result overload is not reported as auth.
    print('PASS: compiled hooks, i386 TLS, native arguments, unchanged success/rejection callbacks')

    # Both native checks can reject the ticket. Preserve the real rejection
    # and expose the two results instead of suggesting the retry succeeded.
    ticket_app = 440
    assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 4
    assert m.ticket_traces[-1] == (peer, 730, 4, 4, 4, 100)
    before = len(registrations)
    assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 1
    assert len(registrations) == before
    ticket_app = 4465480
    print('PASS: wrong-game rejection preserved and original/archive results logged separately')

    entry = m.alloc(bytes(0x8c))
    m.put32(server + 0x1700, entry)
    for existing_app, next_app in [(4465480, 730), (730, 4465480)]:
        for state in [1, 3]:
            m.put32(server + 0x170c, 0)
            ticket_app = existing_app
            assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
            assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 0
            m.cpu.mem_write(entry, struct.pack('<IIQQ', state, 0, peer, existing_app))
            m.put32(server + 0x170c, 1)
            ticket_app = next_app
            before = len(registrations)
            assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
            assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 2
            assert len(registrations) == before # Bridge rejected before the original registrar.
            expected_prefix = b'You are connected via Bridge' if existing_app == 4465480 else b'You are bypassing Bridge'
            assert client_command() == expected_prefix + b' 0.4.3\n' + copyright
            assert m.get32(server + 0x170c) == 1
            if existing_app == 4465480:
                assert m.method(6, error, 256) == 0 # Do not strand archived sessions on unload.
                assert m.method(5, error, 256) == 1
            m.call(hooks['end'], server, low, high, game)
            assert m.get32(server + 0x170c) == 0
            assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
            assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 0
    # For the same AppId, keep the native DuplicateRequest response.
    ticket_app = 730
    m.cpu.mem_write(entry, struct.pack('<IIQQ', 1, 0, peer, 730))
    m.put32(server + 0x170c, 1)
    before = len(registrations)
    assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
    assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 2
    assert len(registrations) == before + 1
    m.call(hooks['end'], server, low, high, game)
    print('PASS: same SteamID 4465480 -> 730 and 730 -> 4465480 return 2 in native states 1/3')
    print('PASS: original same-AppId duplicate result preserved; reconnect succeeds after EndAuthSession')

    for outer_app, inner_app in [(4465480, 730), (730, 4465480)]:
        before = len(registrations)
        m.cpu.reg_write(UC_X86_REG_EBP, 0x700fff00)
        ticket_app = outer_app
        assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
        m.cpu.reg_write(UC_X86_REG_EBP, 0x700ffd00)
        ticket_app = inner_app
        assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
        assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 0
        m.cpu.reg_write(UC_X86_REG_EBP, 0x700fff00)
        assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 0
        assert [x[0] for x in registrations[before:]] == [inner_app, outer_app]
    m.cpu.reg_write(UC_X86_REG_EBP, 0)
    before = len(registrations)
    ticket_app = 4465480
    assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
    m.current_tid = 202
    ticket_app = 730
    assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low, high) == 0
    assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 0
    m.current_tid = 101
    assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 0
    assert [x[0] for x in registrations[before:]] == [730, 4465480]
    assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low, high, handle, 0) == 1
    print('PASS: compiled nested frame routing, independent thread TLS and missing-frame rejection')
    before = len(registrations)
    assert m.call(hooks['verify'], server, game, ticket, 100, offset, identity, low + 1, high) == 0
    assert m.call(hooks['register'], server, 1, game, ticket, 100, 40, low + 1, high, handle, 0) == 1
    assert len(registrations) == before
    print('PASS: mismatched ticket identity cancels its routing frame')




    assert m.method(6, error, 256) == 0
    assert m.method(5, error, 256) == 1
    print('PASS: committed hooks remain active; hot unload refused even with an empty session vector')

    for label, kwargs in [('old engine bypass', {'old_bypass': True}),
                          ('unknown build', {'bad_build': True}),
                          ('permission preflight failure before any instruction writes', {'fail_write': True}),
                          ('busy native mutex prevents code writes', {'busy_mutex': True}),
                          ('unavailable membarrier prevents code writes', {'fail_barrier': True}),
                          ('modified native lock proof prevents code writes', {'bad_lock': True})]:
        m = Machine(**kwargs)
        error = m.alloc(bytes(256))
        assert m.load() == 0, label
        m.original_calls()
        if kwargs.get('fail_write'):
            assert m.failed_once
        print('PASS:', label)

    m = Machine()
    error = m.alloc(bytes(256))
    assert m.load(late=1) == 0
    m.original_calls()
    print('PASS: late loading refused without patches')

    m = Machine(missing_steam=True)
    assert m.load() == 1 and m.bootstrap_args is not None and m.listener
    assert m.method(5, m.error, 256) == 0
    m.original_calls()
    hookman = m.bootstrap_args[5]
    info_vtable = m.alloc(struct.pack('<I', m.external('sh_SetInfo')))
    info = m.alloc(struct.pack('<I', info_vtable))
    assert m.call(hookman, 0, info) == 0
    assert m.hook_info[1:4] == [1, 0, 30] # Linux CSGO Think, excluding the Xbox-only slot.
    m.infos = m.all_infos.copy()
    m.steam_api_ready = True
    delegate = m.bootstrap_args[6]
    delegate_call = m.get32(m.get32(delegate) + 8)
    m.call(delegate_call, delegate, 1)
    assert m.method(5, m.error, 256) == 1 and m.removed_hooks == [73, 74]
    assert m.method(7, m.error, 256) == 0 # Pausing active auth patches is refused.
    assert m.method(6, m.error, 256) == 0
    print('PASS: deferred startup, bootstrap removal and process-lifetime hook policy')

    expected = {9: 'NeDIAD', 10: 'Bridge', 11: 'Proper fix for archived CS:GO, with compatibility layer.',
                12: 'github.com/NeDIAD/bridge', 13: 'GPL-3.0', 14: '0.4.3', 16: 'bridge'}
    for index, value in expected.items():
        assert m.string(m.method(index)).decode('utf-8') == value
    code = m.alloc(bytes(4))
    assert m.call(m.symbols['CreateInterface'], m.alloc(b'GetSMExtAPI\0'), code) == 0
    assert m.get32(code) == 1
    print('PASS: Metamod metadata, correct interface name and no SourceMod factory')

    m = Machine(isolated_steam=True, engine_alias=True)
    assert m.load() == 1
    assert m.method(5, m.error, 256) == 1
    assert m.namespace_probes == [0, 1, 2, 3] # The pinned snapshot is reused.
    assert any(b'found Steamclient' in msg for msg in m.log_formats)
    assert len(m.protection_calls) == 2
    print('PASS: isolated Steamclient namespace discovery and engine_srv alias with original profile checks')

    m = Machine(isolated_steam=True, bad_build=True)
    assert m.load() == 0
    m.original_calls()
    assert any(msg == b'ERROR: %s' for msg in m.log_formats)
    print('PASS: isolated Steamclient with unsupported build is rejected and logged')

    m = Machine(isolated_steam=True, api_ready=False)
    assert m.load() == 1 and m.method(5, m.error, 256) == 0
    m.original_calls()
    assert not m.namespace_probes
    m.steam_api_ready = True
    m.method(4)
    assert m.method(5, m.error, 256) == 1 and m.removed_hooks == [73, 74]
    print('PASS: isolated Steamclient delayed initialization retries without initializing Steam itself')

    m = Machine(isolated_steam=True, wrong_namespace_base=True)
    assert m.load() == 0 and not m.protection_calls
    m.original_calls()
    print('PASS: namespace handle for a different module base never receives patches')

    # Hibernating startup: no GameFrame is emitted. Steam activates only
    # after AllPluginsLoaded/LevelInit; its dedicated event must install hooks.
    m = Machine(isolated_steam=True, api_ready=False)
    assert m.load() == 1 and m.method(5, m.error, 256) == 0
    m.method(4) # Too early; still no native Steam game-server user.
    m.original_calls()
    assert m.activation_args[7] == 1 and m.bootstrap_args[7] == 1
    manager = m.activation_args[5]
    info_vtable = m.alloc(struct.pack('<I', m.external('sh_SetInfo')))
    assert m.call(manager, 0, m.alloc(struct.pack('<I', info_vtable))) == 0
    assert m.hook_info[1:4] == [1, 0, 36]
    delegate = m.activation_args[6]
    delegate_call = m.get32(m.get32(delegate) + 8)
    m.steam_api_ready = True
    m.call(delegate_call, delegate, 0) # Deactivation is never readiness.
    assert m.method(5, m.error, 256) == 0 and not m.protection_calls
    m.call(delegate_call, delegate, 1)
    assert m.method(5, m.error, 256) == 1 and m.removed_hooks == [73, 74]
    print('PASS: Steam activation event installs hooks without any GameFrame or maps inventory')

    m = Machine(isolated_steam=True, api_ready=False)
    assert m.load() == 1 and m.method(5, m.error, 256) == 0
    m.steam_api_ready = True
    delegate = m.bootstrap_args[6]
    m.call(m.get32(m.get32(delegate) + 8), delegate, 1)
    assert m.method(5, m.error, 256) == 1 and m.removed_hooks == [73, 74]
    print('PASS: Think fallback installs hooks without simulation/GameFrame')

    m = Machine(isolated_steam=True, interface_ready=False)
    assert m.load() == 1 and m.method(5, m.error, 256) == 0 and not m.namespace_probes
    m.interface_ready = True
    m.method(4)
    assert m.method(5, m.error, 256) == 1
    print('PASS: existing game-server user with a temporarily null interface waits without patching')

    m = Machine(isolated_steam=True, server_api_exports=False)
    assert m.load() == 1 and m.method(5, m.error, 256) == 1
    print('PASS: legacy exported SteamClient020 accessor fallback')

    m = Machine(isolated_steam=True, server_api_exports=False, api_symbol=False)
    assert m.load() == 0 and not m.protection_calls
    m.original_calls()
    print('PASS: missing Steam API accessors produce a load error without patches')

    m = Machine(isolated_steam=True, api_ready=False, fail_activation=True)
    assert m.load() == 0 and m.removed_hooks == [73, 75]
    m.original_calls()
    print('PASS: partial bootstrap setup failure removes the already registered Think hook')

    m = Machine(missing_steam=True)
    assert m.load() == 1
    assert m.method(6, m.error, 256) == 1
    m.infos = m.all_infos.copy()
    m.steam_api_ready = True
    m.method(4) # A late retry after cancellation must not install anything.
    m.original_calls()
    print('PASS: pending initialization cancellation prevents later installation')

    m = Machine(blocked_peer=True)
    assert m.load() == 1 and not m.queued_signals
    assert m.barriers == [0, 64, 32, 32] and not m.native_lock_held
    assert m.observer_registrations == 1
    print('PASS: blocked RT signal peer cannot prevent native-lock installation; no signals sent')

    m = Machine(fail_sync_after_write=True)
    assert m.load() == 0 and not m.native_lock_held
    assert m.method(6, m.error, 256) == 0
    for item in m.profile['sites']:
        site = m.STEAM + int(item['rva'], 16)
        displacement = struct.unpack('<i', m.cpu.mem_read(site + 1, 4))[0]
        assert m.EXT <= site + 5 + displacement < m.EXT + 0x10000
    print('PASS: post-write synchronization failure retains complete hooks and refuses unload')

    m = Machine(fail_rx=True)
    assert m.load() == 0 and m.rx_failed
    for item in m.profile['sites']:
        site = m.STEAM + int(item['rva'], 16)
        call = bytes(m.cpu.mem_read(site, 5))
        target = (site + 5 + struct.unpack_from('<i', call, 1)[0]) & 0xffffffff
        assert m.EXT <= target < m.EXT + 0x10000
    assert m.method(6, m.error, 256) == 0
    print('PASS: RX restore failure never exposes a partially rolled-back hook set')




if __name__ == '__main__':
    fixtures = fixture_directory()
    FIXTURE_BYTES = {name: read_fixture(fixtures, name) for name in ('engine', 'steamclient')}
    run()


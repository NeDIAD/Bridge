"""Verify the pinned normal control flow keeps check/register/end under lock."""
from pathlib import Path
import json
import re
from fixture_support import fixture_directory, read_fixture

ROOT = Path(__file__).resolve().parent.parent
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM

profile = json.loads((ROOT / 'analysis/profile.json').read_text())
data = read_fixture(fixture_directory(), 'steamclient')
decoder = Cs(CS_ARCH_X86, CS_MODE_32)
decoder.detail = True


def check(start, length, protected):
    instructions = {i.address: i for i in decoder.disasm(data[start:start + length], start)}
    assert data[start:start + 3] == b'\x55\x89\xe5' or start == 0x489550
    pending = [(start, 0)]
    seen = set()
    reached = set()
    returns = 0
    while pending:
        address, depth = pending.pop()
        if (address, depth) in seen:
            continue
        seen.add((address, depth))
        ins = instructions[address]
        next_address = address + ins.size
        immediate = ins.operands[0].imm if ins.operands and ins.operands[0].type == X86_OP_IMM else None
        if ins.mnemonic == 'call':
            if immediate == 0x10cd90: # pthread_mutex_lock PLT
                depth += 1
            elif immediate == 0x10cda0: # pthread_mutex_unlock PLT
                depth -= 1
            if address in protected:
                assert depth == 1, (hex(address), depth)
                reached.add(address)
            assert 0 <= depth <= 1, (hex(address), depth)
        if ins.mnemonic.startswith('ret'):
            assert depth == 0, hex(address)
            returns += 1
            continue
        if ins.mnemonic == 'jmp':
            if immediate in instructions:
                pending.append((immediate, depth))
            # Cold C++ unwind targets outside the function are not normal exits.
            continue
        if ins.mnemonic.startswith('j') and immediate in instructions:
            pending.append((immediate, depth))
        if next_address in instructions:
            pending.append((next_address, depth))
    assert reached == set(protected) and returns > 0


check(0x4890e0, 0x442, [0x4891aa, 0x489325])
check(0x489550, 0x568, [0x48992d])
print('PASS: pinned native CFG holds mutex across Verify/Register and End; normal returns unlock it')

# Runtime compares full native caller bodies, not only hook-site contexts.
header = (ROOT / 'src/native_lock_profile.h').read_text()
for name, start, length in [('kBeginCode', 0x4890e0, 0x442), ('kEndCode', 0x489550, 0x568)]:
    body = re.search(r'unsigned char ' + name + r'\[\] = \{(.*?)\};', header, re.S).group(1)
    expected = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-f]{2})', body))
    assert expected == data[start:start + length]
# PIC thunk return + GOT adjustment + LEA offset resolves the same mutex.
assert 0x4890ea + decoder.disasm(data[0x4890ea:0x4890f0], 0x4890ea).__next__().operands[1].imm + 0x2f918 == 0x22ec278
assert 0x489555 + decoder.disasm(data[0x489555:0x48955a], 0x489555).__next__().operands[1].imm + 0x2f918 == 0x22ec278
print('PASS: full runtime lock-proof bytes match native callers; both resolve mutex RVA 0x22ec278')

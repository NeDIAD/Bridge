"""Execute the actual freestanding Linux i386 tests on Windows using Unicorn."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_INTR
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EBX

cpu = Uc(UC_ARCH_X86, UC_MODE_32)
pages = set()
with (ROOT / 'build/tests/route_tests.i386').open('rb') as stream:
    elf = ELFFile(stream)
    assert elf.elfclass == 32 and elf['e_machine'] == 'EM_386'
    for segment in elf.iter_segments():
        if segment['p_type'] != 'PT_LOAD' or not segment['p_memsz']:
            continue
        start = segment['p_vaddr']
        stop = start + segment['p_memsz']
        for address in range(start & ~4095, (stop + 4095) & ~4095, 4096):
            if address not in pages:
                cpu.mem_map(address, 4096)
                pages.add(address)
        cpu.mem_write(start, segment.data())
    entry = elf['e_entry']

cpu.mem_map(0x70000000, 0x100000)
cpu.reg_write(UC_X86_REG_ESP, 0x700ff000)
exit_codes = []


def interrupt(cpu, number, _):
    assert number == 0x80 and cpu.reg_read(UC_X86_REG_EAX) == 1
    exit_codes.append(cpu.reg_read(UC_X86_REG_EBX))
    cpu.emu_stop()


cpu.hook_add(UC_HOOK_INTR, interrupt)
cpu.emu_start(entry, 0, count=5_000_000)
assert exit_codes == [0], f'Route tests failed at source line: {exit_codes}'
print('PASS: compiled Linux i386 route tests (native ABI, emulated CPU)')

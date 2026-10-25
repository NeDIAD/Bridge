import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--zig', default=os.environ.get('ZIG'))
    args = parser.parse_args()
    candidates = [args.zig, shutil.which('zig')]
    package = importlib.util.find_spec('ziglang')
    
    if package and package.submodule_search_locations:
        candidates += [Path(directory) / name
                       for directory in package.submodule_search_locations
                       for name in ('zig', 'zig.exe')]
        
    zig = next((str(p) for p in candidates if p and Path(p).is_file()), None)
    if not zig:
        raise SystemExit('Zig not found. Supply --zig PATH or set ZIG. Required version: 0.15.2.')
        
    version = subprocess.check_output([zig, 'version'], text=True).strip()
    if version != '0.15.2':
        raise SystemExit(f'Expected Zig 0.15.2, got {version}')
        
    env = os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR'] = str(ROOT / '.cache/zig-global')
    env['ZIG_LOCAL_CACHE_DIR'] = str(ROOT / '.cache/zig-local')
    out = ROOT / 'dist/addons/bridge/bin'
    out.mkdir(parents=True, exist_ok=True)
    
    common = [zig, 'c++', '-target', 'x86-linux-gnu.2.17', '-std=c++17', '-O2',
              '-fno-exceptions', '-fno-rtti', '-Wall', '-Wextra', '-Werror']
    
    subprocess.run(common + ['-g', '-shared', '-fPIC', '-fvisibility=hidden',
                   '-nostdlib++', '-Wl,--no-undefined', '-Wl,-z,relro,-z,now',
                   '-Wl,-soname,bridge_mm_i486.so', '-DMETA_NO_HL2SDK',
                   '-Wl,--version-script=src/bridge.exports',
                   '-isystem', 'third_party/metamod-source/core',
                   '-isystem', 'third_party/metamod-source/core/sourcehook',
                   'src/bridge.cpp', '-ldl',
                   '-o', str(out / 'bridge_mm_i486.so')], cwd=ROOT, env=env, check=True)
    
    metamod = ROOT / 'dist/addons/metamod'
    metamod.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'addons/metamod/bridge.vdf', metamod / 'bridge.vdf')
    
    print(out / 'bridge_mm_i486.so')
    print(metamod / 'bridge.vdf')


if __name__ == '__main__':
    main()

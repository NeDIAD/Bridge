"""Locate privately supplied server binaries and verify the supported profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fixture_directory():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path,
                        default=Path(os.environ.get('BRIDGE_FIXTURES', ROOT / 'tests/fixtures')),
                        help='Serverfiles directory containing bin/engine.so and bin/steamclient.so')
    return parser.parse_args().fixtures.resolve()


def read_fixture(directory, module):
    profile = json.loads((ROOT / 'analysis/profile.json').read_text(encoding='utf-8'))[module]
    path = directory / profile['file']
    if not path.is_file():
        raise SystemExit(f'Missing fixture: {path}. Supply --fixtures SERVERFILES or BRIDGE_FIXTURES.')
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != profile['sha256']:
        raise SystemExit(f'Unsupported fixture {path}: SHA256 {actual}; expected {profile["sha256"]}')
    return data

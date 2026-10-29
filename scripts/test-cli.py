#!/usr/bin/env python3
"""CLI contract checks, for native and JVM launchers."""
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
raw_args = sys.argv[1:] or [str(root / 'dist' / ('ocisim.exe' if os.name == 'nt' else 'ocisim'))]
if len(raw_args) == 1 and raw_args[0].endswith('.jar'):
    java = 'java'
    fallback = Path('/tmp/graalvm-community-openjdk-25.0.2+10.1/bin/java')
    if fallback.is_file() and '25' not in os.environ.get('JAVA_HOME', ''):
        java = str(fallback)
    command = [java, '-jar', str(Path(raw_args[0]).resolve())]
else:
    command = list(raw_args)

def run(args, code=0):
    p = subprocess.run(command + args, capture_output=True, text=True, timeout=30)
    assert p.returncode == code, (args, p.returncode, p.stdout, p.stderr)
    return p.stdout

assert run(['--version']).strip() == 'ocisim ' + (root / 'VERSION').read_text(encoding='utf-8').strip() + ' (floci-oci 0.5.0)'
assert '127.0.0.1' in run(['--help'])
assert '127.0.0.1' in run(['-h'])
for args in [
    [],
    ['bogus'],
    ['serve', '--port'],
    ['serve', '--port', '0'],
    ['serve', '--port', '65536'],
    ['serve', '--port', 'x'],
    ['serve', '--wat', 'x'],
    ['start', '--data-dir', ''],
    ['serve', '--port', '1234', '--port', '1235'],
]:
    payload = json.loads(run(args, 2))
    assert payload['ok'] is False and payload['error']['kind'] == 'usage', (args, payload)
print('CLI: 12 checks passed')

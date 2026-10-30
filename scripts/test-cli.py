#!/usr/bin/env python3
"""CLI contract checks, for native and JVM launchers."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

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

BASE_ENV = {
    k: v
    for k, v in os.environ.items()
    if not k.startswith(('OCISIM_AUTH', 'SIM_AUTH'))
}


def run(args, code=0, extra_env=None):
    env = dict(BASE_ENV)
    if extra_env:
        env.update(extra_env)
    p = subprocess.run(command + args, env=env, capture_output=True, text=True, timeout=30)
    assert p.returncode == code, (args, p.returncode, p.stdout, p.stderr)
    return p.stdout


assert run(['--version']).strip() == 'ocisim ' + (root / 'VERSION').read_text(encoding='utf-8').strip() + ' (floci-oci 0.5.0)'
help_out = run(['--help'])
assert '127.0.0.1' in help_out and '--auth open|enforce' in help_out and '--auth-config FILE' in help_out
assert '127.0.0.1' in run(['-h'])

with tempfile.TemporaryDirectory(prefix='ocisim-cli-test-') as tmp:
    tmp_dir = Path(tmp)
    bad_json = tmp_dir / 'bad.json'
    bad_json.write_text('{not-json', encoding='utf-8')
    empty_creds = tmp_dir / 'empty.json'
    empty_creds.write_text('{"credentials":[]}', encoding='utf-8')
    bad_policy = tmp_dir / 'bad-policy.json'
    bad_policy.write_text(
        json.dumps({
            'credentials': [{
                'keyId': 't/u/f',
                'publicKeyPem': '-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----',
            }]
        }),
        encoding='utf-8',
    )

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
        ['serve', '--auth'],
        ['serve', '--auth', 'invalid'],
        ['serve', '--auth', 'open', '--auth', 'enforce'],
        ['serve', '--auth-config'],
        ['serve', '--auth-config', str(bad_json), '--auth-config', str(bad_json)],
        ['serve', '--auth', 'enforce'],
        ['serve', '--auth', 'enforce', '--auth-config', str(tmp_dir / 'missing.json')],
        ['serve', '--auth', 'enforce', '--auth-config', str(bad_json)],
        ['serve', '--auth', 'enforce', '--auth-config', str(empty_creds)],
        ['serve', '--auth', 'enforce', '--auth-config', str(bad_policy)],
    ]:
        payload = json.loads(run(args, 2))
        assert payload['ok'] is False and payload['error']['kind'] == 'usage', (args, payload)

    env_payload_1 = json.loads(run(['serve'], 2, extra_env={'OCISIM_AUTH': 'bogus'}))
    assert env_payload_1['ok'] is False and env_payload_1['error']['message'] == 'auth must be open or enforce'

    env_payload_2 = json.loads(run(['serve'], 2, extra_env={'SIM_AUTH': 'enforce'}))
    assert env_payload_2['ok'] is False and env_payload_2['error']['message'] == 'invalid or unreadable auth config'

print('CLI: 24 checks passed')

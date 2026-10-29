#!/usr/bin/env python3
"""Real OCI Object Storage, Identity, and Queue lifecycle tests against our own process."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
raw_args = sys.argv[1:] or [str(ROOT / 'dist' / ('ocisim.exe' if os.name == 'nt' else 'ocisim'))]
if len(raw_args) == 1 and raw_args[0].endswith('.jar'):
    java = 'java'
    fallback = Path('/tmp/graalvm-community-openjdk-25.0.2+10.1/bin/java')
    if fallback.is_file() and '25' not in os.environ.get('JAVA_HOME', ''):
        java = str(fallback)
    COMMAND = [java, '-jar', str(Path(raw_args[0]).resolve())]
else:
    COMMAND = list(raw_args)
    if Path(COMMAND[0]).is_file():
        COMMAND[0] = str(Path(COMMAND[0]).resolve())

# Never consult a user's OCI config, cloud credentials, proxy, or endpoint overrides.
ENV = {
    k: v
    for k, v in os.environ.items()
    if not k.startswith(('OCI_', 'FLOCI_', 'QUARKUS_')) and 'proxy' not in k.lower()
}

TENANCY = 'ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000'
USER = 'ocid1.user.oc1..flocilocaluser00000000000000000000000000000000000000000000'
FINGERPRINT = 'aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99'
TENANCY_B = 'ocid1.tenancy.oc1..secondlocaltenancy000000000000000000000000000000000000000'

with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
endpoint = f'http://127.0.0.1:{port}'
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
checks = []


def oci_auth_header(tenancy=TENANCY, user=USER, fingerprint=FINGERPRINT):
    key_id = f'{tenancy}/{user}/{fingerprint}'
    return (
        f'Signature version="1",keyId="{key_id}",algorithm="rsa-sha256",'
        'headers="(request-target) date host",signature="dummysignature==",'
        'version="1"'
    )


def request(method, path, body=None, status=200, headers=None, tenancy=TENANCY):
    req_headers = {
        'Authorization': oci_auth_header(tenancy=tenancy),
        'Date': 'Thu, 29 Oct 2026 18:00:00 GMT',
    }
    if body is not None and not isinstance(body, (bytes, bytearray)):
        body = json.dumps(body).encode('utf-8')
        req_headers['Content-Type'] = 'application/json'
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(endpoint + path, data=body, method=method, headers=req_headers)
    try:
        response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read()
        assert response.status == status, (method, path, response.status, content)
        return content, response.headers


@contextmanager
def running_server(directory, persistent=True, subcommand='serve'):
    log_path = directory / f'server-{subcommand}.log'
    with log_path.open('w+', encoding='utf-8', errors='replace') as log:
        args = COMMAND + [subcommand, '--port', str(port)]
        if persistent:
            args += ['--data-dir', str(directory / 'state')]
        server = subprocess.Popen(args, env=ENV, cwd=directory, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 90
            while True:
                assert server.poll() is None, 'server exited before readiness'
                try:
                    with opener.open(endpoint + '/_floci-oci/health', timeout=1) as resp:
                        if resp.status == 200:
                            break
                except (OSError, TimeoutError):
                    pass
                assert time.monotonic() < deadline, 'readiness timeout'
                time.sleep(0.2)
            yield server
        except BaseException:
            log.flush()
            print(log_path.read_text(encoding='utf-8', errors='replace'), file=sys.stderr)
            raise
        finally:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def run_oci_cli_checks(directory):
    oci_bin = shutil.which(os.environ.get('OCI_CLI_BIN', 'oci'))
    if not oci_bin and Path('/tmp/oci-cli-venv/bin/oci').is_file():
        oci_bin = '/tmp/oci-cli-venv/bin/oci'
    if not oci_bin:
        return False

    oci_dir = directory / '.oci'
    oci_dir.mkdir(exist_ok=True)
    key_file = oci_dir / 'key.pem'
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            + b'OCI_API_KEY\n'
        )
    except ImportError:
        openssl = shutil.which('openssl')
        if not openssl:
            return False
        subprocess.run([openssl, 'genrsa', '-out', str(key_file), '2048'], check=True, capture_output=True)
        with key_file.open('ab') as f:
            f.write(b'OCI_API_KEY\n')
    key_file.chmod(0o600)
    cfg_file = oci_dir / 'config'
    cfg_file.write_text(
        '[DEFAULT]\n'
        f'user={USER}\n'
        f'fingerprint={FINGERPRINT}\n'
        f'key_file={key_file}\n'
        f'tenancy={TENANCY}\n'
        'region=us-ashburn-1\n',
        encoding='utf-8',
    )
    cfg_file.chmod(0o600)
    cli_env = {
        **ENV,
        'OCI_CLI_CONFIG_FILE': str(cfg_file),
        'OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING': 'True',
    }

    def oci(*args):
        p = subprocess.run(
            [oci_bin, '--config-file', str(cfg_file), '--endpoint', endpoint, '--output', 'json', *args],
            env=cli_env,
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=45,
        )
        assert p.returncode == 0, (args, p.stdout, p.stderr)
        return json.loads(p.stdout) if p.stdout.strip() else {}

    ns = oci('os', 'ns', 'get')['data']
    assert ns == 'floci-local', ns
    oci('os', 'bucket', 'create', '--compartment-id', TENANCY, '--namespace-name', ns, '--name', 'oci-cli-bucket')
    cli_payload = b'oci-cli binary round trip\x00\xfe\n'
    src_file = directory / 'cli-in.bin'
    dst_file = directory / 'cli-out.bin'
    src_file.write_bytes(cli_payload)
    oci('os', 'object', 'put', '--namespace-name', ns, '--bucket-name', 'oci-cli-bucket', '--name', 'item.bin', '--file', str(src_file), '--force')
    oci('os', 'object', 'get', '--namespace-name', ns, '--bucket-name', 'oci-cli-bucket', '--name', 'item.bin', '--file', str(dst_file))
    assert dst_file.read_bytes() == cli_payload
    oci('os', 'object', 'delete', '--namespace-name', ns, '--bucket-name', 'oci-cli-bucket', '--name', 'item.bin', '--force')
    oci('os', 'bucket', 'delete', '--namespace-name', ns, '--bucket-name', 'oci-cli-bucket', '--force')
    regions = oci('iam', 'region', 'list')['data']
    assert any(r.get('name') == 'us-ashburn-1' for r in regions), regions
    return True


with tempfile.TemporaryDirectory(prefix='ocisim-test-') as tmp:
    directory = Path(tmp)
    with running_server(directory, persistent=True, subcommand='serve'):
        # 1. Occupied port must fail with exit code 3 and JSON error envelope
        busy = subprocess.run(
            COMMAND + ['start', '--port', str(port)],
            env=ENV,
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=45,
        )
        assert busy.returncode == 3, (busy.returncode, busy.stdout, busy.stderr)
        assert json.loads(busy.stdout)['ok'] is False
        checks.append('occupied-port exit 3')

        # 2. Health endpoint
        health_body, _ = request('GET', '/_floci-oci/health')
        health = json.loads(health_body)
        assert 'services' in health and health.get('edition') == 'community', health
        checks.append('health endpoint')

        # 3. Object Storage: namespace, bucket create/get/list, object put/head/get/list/rename
        ns_body, ns_headers = request('GET', '/n/')
        ns = json.loads(ns_body)
        assert ns == 'floci-local', ns
        assert 'opc-request-id' in {k.lower() for k in ns_headers.keys()}

        bucket_body, _ = request(
            'POST',
            f'/n/{ns}/b/',
            {'name': 'ocisim-roundtrip', 'compartmentId': TENANCY},
            status=200,
        )
        assert json.loads(bucket_body)['name'] == 'ocisim-roundtrip'

        get_b_body, _ = request('GET', f'/n/{ns}/b/ocisim-roundtrip')
        assert json.loads(get_b_body)['name'] == 'ocisim-roundtrip'

        list_b_body, _ = request('GET', f'/n/{ns}/b/?compartmentId={ urllib.parse.quote(TENANCY) }')
        assert any(b['name'] == 'ocisim-roundtrip' for b in json.loads(list_b_body))

        payload = b'ocisim real OCI object storage round trip\x00\xff\n'
        _, put_headers = request(
            'PUT',
            f'/n/{ns}/b/ocisim-roundtrip/o/test.bin',
            payload,
            status=200,
            headers={'Content-Type': 'application/octet-stream', 'opc-meta-origin': 'ocisim-suite'},
        )
        assert put_headers.get('ETag') or put_headers.get('etag')

        _, head_headers = request('HEAD', f'/n/{ns}/b/ocisim-roundtrip/o/test.bin', status=200)
        assert head_headers.get('opc-meta-origin') == 'ocisim-suite'

        got_bytes, _ = request('GET', f'/n/{ns}/b/ocisim-roundtrip/o/test.bin', status=200)
        assert got_bytes == payload

        list_o_body, _ = request('GET', f'/n/{ns}/b/ocisim-roundtrip/o')
        objects = json.loads(list_o_body)['objects']
        assert [o['name'] for o in objects] == ['test.bin'], objects

        request(
            'POST',
            f'/n/{ns}/b/ocisim-roundtrip/actions/renameObject',
            {'sourceName': 'test.bin', 'newName': 'renamed.bin'},
            status=200,
        )
        request('GET', f'/n/{ns}/b/ocisim-roundtrip/o/test.bin', status=404)
        renamed_bytes, _ = request('GET', f'/n/{ns}/b/ocisim-roundtrip/o/renamed.bin', status=200)
        assert renamed_bytes == payload
        checks.append('Object Storage namespace/bucket/put/head/get/list/rename byte equality')

        # 4. Multi-tenancy isolation via OCI Signature keyId tenancy partition
        ns_b_body, _ = request('GET', '/n/', tenancy=TENANCY_B)
        ns_b = json.loads(ns_b_body)
        list_b_tenancy2, _ = request(
            'GET',
            f'/n/{ns_b}/b/?compartmentId={urllib.parse.quote(TENANCY_B)}',
            tenancy=TENANCY_B,
        )
        assert json.loads(list_b_tenancy2) == []
        checks.append('multi-tenancy signature isolation')

        # 5. Identity (IAM) regions and compartment CRUD
        regions_body, _ = request('GET', '/20160918/regions')
        assert any(r['name'] == 'us-ashburn-1' for r in json.loads(regions_body))
        comp_body, _ = request(
            'POST',
            '/20160918/compartments',
            {
                'compartmentId': TENANCY,
                'name': 'ocisim-compartment',
                'description': 'test compartment',
            },
            status=200,
        )
        comp_id = json.loads(comp_body)['id']
        comps_list, _ = request('GET', f'/20160918/compartments?compartmentId={urllib.parse.quote(TENANCY)}')
        assert any(c['id'] == comp_id for c in json.loads(comps_list))
        checks.append('Identity regions and compartment create/list')

        # 6. Queue service create, put/get/delete message, delete queue
        _, q_headers = request(
            'POST',
            '/20210201/queues',
            {'compartmentId': TENANCY, 'displayName': 'ocisim-queue'},
            status=202,
        )
        assert q_headers.get('opc-work-request-id')
        q_list_body, _ = request('GET', f'/20210201/queues?compartmentId={urllib.parse.quote(TENANCY)}')
        queues = json.loads(q_list_body)['items']
        queue_id = next(q['id'] for q in queues if q['displayName'] == 'ocisim-queue')

        request(
            'POST',
            f'/20210201/queues/{queue_id}/messages',
            {'messages': [{'content': 'ocisim queue message'}]},
            status=200,
        )
        msg_body, _ = request(
            'GET',
            f'/20210201/queues/{queue_id}/messages?visibilityInSeconds=30&timeoutInSeconds=1&limit=1',
            status=200,
        )
        messages = json.loads(msg_body)['messages']
        assert len(messages) == 1 and messages[0]['content'] == 'ocisim queue message', messages
        receipt = messages[0]['receipt']
        request(
            'DELETE',
            f'/20210201/queues/{queue_id}/messages/{urllib.parse.quote(receipt, safe="")}',
            status=204,
        )
        empty_msg_body, _ = request(
            'GET',
            f'/20210201/queues/{queue_id}/messages?visibilityInSeconds=30&timeoutInSeconds=0&limit=1',
            status=200,
        )
        assert json.loads(empty_msg_body)['messages'] == []
        request('DELETE', f'/20210201/queues/{queue_id}', status=202)
        checks.append('Queue create/put/get/delete message/delete queue')

        # 7. Optional official oci-cli round trip when oci is installed
        if run_oci_cli_checks(directory):
            checks.append('oci-cli bucket/object/iam round trip')

    # 8. Restart with `start` alias and `--data-dir` persistence, then clean up
    with running_server(directory, persistent=True, subcommand='start'):
        persisted_bytes, _ = request('GET', '/n/floci-local/b/ocisim-roundtrip/o/renamed.bin', status=200)
        assert persisted_bytes == payload
        request('DELETE', '/n/floci-local/b/ocisim-roundtrip/o/renamed.bin', status=204)
        request('DELETE', '/n/floci-local/b/ocisim-roundtrip', status=204)
        request('GET', '/n/floci-local/b/ocisim-roundtrip', status=404)
        checks.append('persistent restart via start alias and cleanup')

    # 9. Ephemeral mode starts clean
    with running_server(directory, persistent=False, subcommand='serve'):
        request('GET', '/n/floci-local/b/ocisim-roundtrip', status=404)
        checks.append('ephemeral memory mode isolation')

print(json.dumps({'ok': True, 'checks': checks, 'leftovers': 0}, indent=2))

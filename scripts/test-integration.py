#!/usr/bin/env python3
"""Real OCI Object Storage, Identity, Queue, Auth/IAM Policy, and lmoci integration tests."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
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


def resolve_java():
    fallback = Path('/tmp/graalvm-community-openjdk-25.0.2+10.1/bin/java')
    if fallback.is_file() and '25' not in os.environ.get('JAVA_HOME', ''):
        return str(fallback)
    java_home = os.environ.get('JAVA_HOME', '')
    if java_home:
        candidate = Path(java_home) / 'bin' / ('java.exe' if os.name == 'nt' else 'java')
        if candidate.is_file():
            return str(candidate)
    return shutil.which('java.exe' if os.name == 'nt' else 'java') or 'java'


JAVA_BIN = resolve_java()

if len(raw_args) == 1 and raw_args[0].endswith('.jar'):
    COMMAND = [JAVA_BIN, '-jar', str(Path(raw_args[0]).resolve())]
else:
    COMMAND = list(raw_args)
    if Path(COMMAND[0]).is_file():
        COMMAND[0] = str(Path(COMMAND[0]).resolve())

# Never consult a user's OCI config, cloud credentials, proxy, or endpoint overrides.
ENV = {
    k: v
    for k, v in os.environ.items()
    if not k.startswith(('OCI_', 'LMOCI_', 'FLOCI_', 'QUARKUS_', 'OCISIM_AUTH', 'SIM_AUTH'))
    and 'proxy' not in k.lower()
}

TENANCY = 'ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000'
USER = 'ocid1.user.oc1..flocilocaluser00000000000000000000000000000000000000000000'
FINGERPRINT = 'aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99'
TENANCY_B = 'ocid1.tenancy.oc1..secondlocaltenancy000000000000000000000000000000000000000'

# Pinned lmctl-ai/lmoci v0.1.0 release binaries and SHA-256 checksums across all 5 platforms.
LMOCI_VERSION = 'v0.1.0'
LMOCI_ASSETS = {
    ('linux', 'x86_64'): (
        'lmoci-linux-x64',
        'a22661745a682e6321cf61fabd6afbcbb10f77f188bae271c0c7db2b1870de65',
    ),
    ('linux', 'aarch64'): (
        'lmoci-linux-arm64',
        'de8b053c6ff8cf683f0fa079a332c8bd69569911b989263a88ca0506feca85f8',
    ),
    ('darwin', 'arm64'): (
        'lmoci-macos-arm64',
        'efa7de19c90e26adde453ecb5a0512308cea9c3fd47bc6fa7d300f277217106a',
    ),
    ('darwin', 'x86_64'): (
        'lmoci-macos-x64',
        '5e565afbaf590f63f553bb5cdda7dd854c1d2df7ff8507ae12383452a00015f9',
    ),
    ('windows', 'amd64'): (
        'lmoci-windows-x64.exe',
        '3f5419d4049928bd6ae1738e7b5ad0ad25ee43f73dfb5b7380b0f2d3779f2326',
    ),
}

with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
endpoint = f'http://127.0.0.1:{port}'
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
checks = []


def detect_lmoci_asset():
    sys_name = sys.platform.lower()
    os_key = 'windows' if sys_name.startswith('win') else ('darwin' if sys_name == 'darwin' else 'linux')
    mach = platform.machine().lower()
    if mach in ('amd64', 'x86_64'):
        arch_key = 'amd64' if os_key == 'windows' else 'x86_64'
    elif mach in ('arm64', 'aarch64'):
        arch_key = 'arm64' if os_key == 'darwin' else 'aarch64'
    else:
        raise RuntimeError(f'Unsupported platform: {sys_name} / {mach}')
    return LMOCI_ASSETS[(os_key, arch_key)]


def ensure_lmoci_binary():
    explicit = os.environ.get('LMOCI_BIN', '')
    if explicit and Path(explicit).is_file():
        return str(Path(explicit).resolve())

    asset_name, expected_sha256 = detect_lmoci_asset()
    cache_dir = ROOT / '.cache' / 'lmoci' / LMOCI_VERSION
    cache_dir.mkdir(parents=True, exist_ok=True)
    binary_path = cache_dir / asset_name
    if binary_path.is_file():
        actual = hashlib.sha256(binary_path.read_bytes()).hexdigest()
        if actual == expected_sha256:
            if os.name != 'nt':
                binary_path.chmod(0o755)
            return str(binary_path)
        binary_path.unlink()

    url = f'https://github.com/lmctl-ai/lmoci/releases/download/{LMOCI_VERSION}/{asset_name}'
    with urllib.request.urlopen(url, timeout=180) as resp:
        data = resp.read()
    actual = hashlib.sha256(data).hexdigest()
    assert actual == expected_sha256, f'lmoci SHA-256 mismatch for {asset_name}: expected {expected_sha256}, got {actual}'
    binary_path.write_bytes(data)
    if os.name != 'nt':
        binary_path.chmod(0o755)
    return str(binary_path)


CRYPTO_HELPER_JAVA = """
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class CryptoHelper {
    public static void main(String[] args) throws Exception {
        if ("keygen".equals(args[0])) {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair pair = gen.generateKeyPair();
            Base64.Encoder mime = Base64.getMimeEncoder(64, "\\n".getBytes(StandardCharsets.US_ASCII));
            String privPem = "-----BEGIN PRIVATE KEY-----\\n"
                    + mime.encodeToString(pair.getPrivate().getEncoded())
                    + "\\n-----END PRIVATE KEY-----\\n";
            String pubPem = "-----BEGIN PUBLIC KEY-----\\n"
                    + mime.encodeToString(pair.getPublic().getEncoded())
                    + "\\n-----END PUBLIC KEY-----\\n";
            Files.writeString(Path.of(args[1]), privPem, StandardCharsets.UTF_8);
            Files.writeString(Path.of(args[2]), pubPem, StandardCharsets.UTF_8);
        } else if ("sign".equals(args[0])) {
            String pem = Files.readString(Path.of(args[1]), StandardCharsets.UTF_8)
                    .replaceAll("-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", "")
                    .replaceAll("-----END [A-Z0-9 ]*PRIVATE KEY-----", "")
                    .replaceAll("\\\\s+", "");
            PrivateKey priv = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
            byte[] signingBytes = Base64.getDecoder().decode(args[2]);
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(priv);
            sig.update(signingBytes);
            System.out.print(Base64.getEncoder().encodeToString(sig.sign()));
        }
    }
}
"""


def generate_rsa_keypair(directory, name):
    priv_path = directory / f'{name}-private.pem'
    pub_path = directory / f'{name}-public.pem'
    helper_file = directory / 'CryptoHelper.java'
    if not helper_file.is_file():
        helper_file.write_text(CRYPTO_HELPER_JAVA, encoding='utf-8')
    subprocess.run(
        [JAVA_BIN, str(helper_file), 'keygen', str(priv_path), str(pub_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if os.name != 'nt':
        priv_path.chmod(0o600)
    return priv_path, pub_path, priv_path.read_text(encoding='utf-8'), pub_path.read_text(encoding='utf-8')


def sign_bytes_rsa_sha256(directory, priv_path, signing_string):
    helper_file = directory / 'CryptoHelper.java'
    b64_input = urllib.parse.quote_from_bytes(b'')  # unused placeholder
    import base64
    b64_payload = base64.b64encode(signing_string.encode('utf-8')).decode('ascii')
    p = subprocess.run(
        [JAVA_BIN, str(helper_file), 'sign', str(priv_path), b64_payload],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return p.stdout.strip()


def oci_auth_header(tenancy=TENANCY, user=USER, fingerprint=FINGERPRINT):
    key_id = f'{tenancy}/{user}/{fingerprint}'
    return (
        f'Signature version="1",keyId="{key_id}",algorithm="rsa-sha256",'
        'headers="(request-target) date host",signature="dummysignature==",'
        'version="1"'
    )


def request(method, path, body=None, status=200, headers=None, tenancy=TENANCY, include_auth=True):
    req_headers = {
        'Date': 'Thu, 29 Oct 2026 18:00:00 GMT',
    }
    if include_auth:
        req_headers['Authorization'] = oci_auth_header(tenancy=tenancy)
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


def signed_request(directory, method, path, key_id, priv_path, body=None, status=200, tamper_body=None):
    import base64
    date_str = 'Thu, 29 Oct 2026 18:00:00 GMT'
    host_str = f'127.0.0.1:{port}'
    req_headers = {
        'Date': date_str,
        'Host': host_str,
    }
    raw_bytes = b''
    if body is not None:
        if not isinstance(body, (bytes, bytearray)):
            raw_bytes = json.dumps(body).encode('utf-8')
            req_headers['Content-Type'] = 'application/json'
        else:
            raw_bytes = bytes(body)
            req_headers['Content-Type'] = 'application/octet-stream'

    if method.upper() in ('POST', 'PUT', 'PATCH') and body is not None:
        sha256_b64 = base64.b64encode(hashlib.sha256(raw_bytes).digest()).decode('ascii')
        req_headers['x-content-sha256'] = sha256_b64
        req_headers['Content-Length'] = str(len(raw_bytes))
        signed_headers = 'date (request-target) host content-length content-type x-content-sha256'
        signing_lines = [
            f'date: {date_str}',
            f'(request-target): {method.lower()} {path}',
            f'host: {host_str}',
            f'content-length: {len(raw_bytes)}',
            f'content-type: {req_headers["Content-Type"]}',
            f'x-content-sha256: {sha256_b64}',
        ]
    else:
        signed_headers = 'date (request-target) host'
        signing_lines = [
            f'date: {date_str}',
            f'(request-target): {method.lower()} {path}',
            f'host: {host_str}',
        ]

    sig_b64 = sign_bytes_rsa_sha256(directory, priv_path, '\n'.join(signing_lines))
    req_headers['Authorization'] = (
        f'Signature version="1",keyId="{key_id}",algorithm="rsa-sha256",'
        f'headers="{signed_headers}",signature="{sig_b64}"'
    )
    wire_body = tamper_body if tamper_body is not None else (raw_bytes if body is not None else None)
    if tamper_body is not None:
        req_headers['Content-Length'] = str(len(tamper_body))
    req = urllib.request.Request(endpoint + path, data=wire_body, method=method, headers=req_headers)
    try:
        response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read()
        assert response.status == status, (method, path, response.status, content)
        return content, response.headers


@contextmanager
def running_server(directory, persistent=True, subcommand='serve', extra_args=None, extra_env=None):
    log_path = directory / f'server-{subcommand}-{int(time.time() * 1000)}.log'
    with log_path.open('w+', encoding='utf-8', errors='replace') as log:
        args = COMMAND + [subcommand, '--port', str(port)]
        if persistent:
            args += ['--data-dir', str(directory / 'state')]
        if extra_args:
            args += list(extra_args)
        run_env = dict(ENV)
        if extra_env:
            run_env.update(extra_env)
        server = subprocess.Popen(args, env=run_env, cwd=directory, stdout=log, stderr=log)
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
    priv_path, _, _, _ = generate_rsa_keypair(oci_dir, 'oci-cli')
    key_file = oci_dir / 'key.pem'
    key_file.write_bytes(priv_path.read_bytes() + b'OCI_API_KEY\n')
    if os.name != 'nt':
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
    if os.name != 'nt':
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


def invoke_lmoci(lmoci_bin, directory, args, cred_env=None, expect_code=0):
    cmd_prefix = [JAVA_BIN, '-jar', lmoci_bin] if lmoci_bin.endswith('.jar') else [lmoci_bin]
    home_dir = directory / 'lmoci-home'
    home_dir.mkdir(exist_ok=True)
    lmoci_env = {
        **ENV,
        'HOME': str(home_dir),
        'USERPROFILE': str(home_dir),
        'LMOCI_ENDPOINT': endpoint,
    }
    if cred_env:
        lmoci_env.update(cred_env)
    p = subprocess.run(
        cmd_prefix + list(args) + ['--endpoint', endpoint],
        env=lmoci_env,
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert 'BEGIN PRIVATE KEY' not in p.stdout and 'BEGIN PRIVATE KEY' not in p.stderr
    assert p.returncode == expect_code, (args, p.returncode, p.stdout, p.stderr)
    payload = json.loads(p.stdout)
    if expect_code == 0:
        assert payload.get('ok') is True, payload
        return payload['result']
    else:
        assert payload.get('ok') is False, payload
        return payload['error']


def run_lmoci_roundtrip(lmoci_bin, directory, cred_env=None, prefix='open'):
    assert invoke_lmoci(lmoci_bin, directory, ['os', 'namespace'], cred_env=cred_env)['namespace'] == 'floci-local'
    bkt = f'lmoci-{prefix}-roundtrip'
    invoke_lmoci(lmoci_bin, directory, ['os', 'create-bucket', bkt], cred_env=cred_env)
    assert invoke_lmoci(lmoci_bin, directory, ['os', 'head-bucket', bkt], cred_env=cred_env)['exists'] is True
    assert invoke_lmoci(
        lmoci_bin,
        directory,
        ['os', 'put-object', bkt, 'hello/world.txt', '--content', 'ocisim-live-payload'],
        cred_env=cred_env,
    )['content_length'] == 19
    assert invoke_lmoci(
        lmoci_bin,
        directory,
        ['os', 'get-object', bkt, 'hello/world.txt'],
        cred_env=cred_env,
    )['content'] == 'ocisim-live-payload'
    assert invoke_lmoci(
        lmoci_bin,
        directory,
        ['os', 'head-object', bkt, 'hello/world.txt'],
        cred_env=cred_env,
    )['exists'] is True
    assert invoke_lmoci(
        lmoci_bin,
        directory,
        ['os', 'list-objects', bkt, 'hello/'],
        cred_env=cred_env,
    )['count'] == 1
    invoke_lmoci(lmoci_bin, directory, ['os', 'rename-object', bkt, 'hello/world.txt', 'hello/moved.txt'], cred_env=cred_env)
    assert invoke_lmoci(
        lmoci_bin,
        directory,
        ['os', 'get-object', bkt, 'hello/moved.txt'],
        cred_env=cred_env,
    )['content'] == 'ocisim-live-payload'
    invoke_lmoci(lmoci_bin, directory, ['os', 'delete-object', bkt, 'hello/moved.txt'], cred_env=cred_env)
    invoke_lmoci(lmoci_bin, directory, ['os', 'delete-bucket', bkt], cred_env=cred_env)

    # Also test IAM compartment + Queue lifecycle through lmoci
    comp = invoke_lmoci(
        lmoci_bin,
        directory,
        ['iam', 'create-compartment', f'lmoci-{prefix}-comp'],
        cred_env=cred_env,
    )
    comp_id = comp['id']
    comps = invoke_lmoci(
        lmoci_bin,
        directory,
        ['iam', 'compartments'],
        cred_env=cred_env,
    )
    assert any(c['id'] == comp_id for c in comps), comps
    invoke_lmoci(
        lmoci_bin,
        directory,
        ['iam', 'delete-compartment', comp_id],
        cred_env=cred_env,
    )

    q = invoke_lmoci(
        lmoci_bin,
        directory,
        ['queue', 'create', f'lmoci-{prefix}-queue'],
        cred_env=cred_env,
    )
    q_id = q['id']
    invoke_lmoci(lmoci_bin, directory, ['queue', 'send', q_id, 'lmoci-msg-1'], cred_env=cred_env)
    msgs = invoke_lmoci(lmoci_bin, directory, ['queue', 'receive', q_id], cred_env=cred_env)['messages']
    assert len(msgs) == 1 and msgs[0]['content'] == 'lmoci-msg-1', msgs
    invoke_lmoci(lmoci_bin, directory, ['queue', 'delete-message', q_id, msgs[0]['receipt']], cred_env=cred_env)
    invoke_lmoci(lmoci_bin, directory, ['queue', 'delete', q_id], cred_env=cred_env)


def resolve_lmscript():
    candidates = [
        os.environ.get('LMSCRIPT_BIN', ''),
        str(Path.home() / 'lmctl-mono' / 'bin' / 'lmscript'),
        shutil.which('lmscript-mono') or '',
        shutil.which('lmscript.cmd' if os.name == 'nt' else 'lmscript') or '',
        shutil.which('lmscript') or '',
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return str(Path(c).resolve())
    return None


@contextmanager
def running_server_on_port(target_port, directory, persistent=False, subcommand='serve', extra_args=None, extra_env=None):
    target_endpoint = f'http://127.0.0.1:{target_port}'
    log_path = directory / f'server-{subcommand}-{target_port}-{int(time.time() * 1000)}.log'
    with log_path.open('w+', encoding='utf-8', errors='replace') as log:
        args = COMMAND + [subcommand, '--port', str(target_port)]
        if persistent:
            args += ['--data-dir', str(directory / f'state-{target_port}')]
        if extra_args:
            args += list(extra_args)
        run_env = dict(ENV)
        if extra_env:
            run_env.update(extra_env)
        server = subprocess.Popen(args, env=run_env, cwd=directory, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 90
            while True:
                assert server.poll() is None, 'server exited before readiness'
                try:
                    with opener.open(target_endpoint + '/_floci-oci/health', timeout=1) as resp:
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


def run_template_lms_checks(lmoci_bin, directory):
    lmscript_bin = resolve_lmscript()
    if not lmscript_bin:
        if os.environ.get('LMSCRIPT_REQUIRED') == '1':
            raise AssertionError('lmscript binary is required when LMSCRIPT_REQUIRED=1')
        return None

    schema_out = subprocess.run(
        [lmoci_bin, '--lmcode-schema', '--json'],
        env=ENV,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    schema_path = ROOT / '.cache' / 'lmoci-schema.json'
    schema_path.parent.mkdir(parents=True, exist_ok=True)
    schema_path.write_text(schema_out.replace('\r\n', '\n'), encoding='utf-8', newline='\n')

    tmpl_dir = directory / 'lms-templates'
    tmpl_dir.mkdir(exist_ok=True)
    generate_rsa_keypair(tmpl_dir, 'admin')
    generate_rsa_keypair(tmpl_dir, 'reader')
    generate_rsa_keypair(tmpl_dir, 'wrong')

    with socket.socket() as s2:
        s2.bind(('127.0.0.1', 0))
        open_p = port
        enforce_p = s2.getsockname()[1]

    lms_file = str(ROOT / 'examples' / 'templates.lms')
    lms_cmd_prefix = ['cmd.exe', '/c', lmscript_bin] if lmscript_bin.lower().endswith('.cmd') else [lmscript_bin]
    lms_env = {
        **ENV,
        'HOME': str(tmpl_dir),
        'USERPROFILE': str(tmpl_dir),
    }

    # Phase 1: generate templated-auth-config.json from _json_ block in templates.lms
    prep = subprocess.run(
        lms_cmd_prefix + ['--no-preflight', lms_file, 'prepare-auth', str(tmpl_dir), lmoci_bin, str(open_p), str(enforce_p)],
        env=lms_env,
        cwd=tmpl_dir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert prep.returncode == 0, (prep.returncode, prep.stdout, prep.stderr)
    prep_info = json.loads(prep.stdout.strip().splitlines()[-1])
    auth_cfg_file = Path(prep_info['auth_config'])
    assert auth_cfg_file.is_file(), auth_cfg_file

    # Phase 2: run full template-driven open + enforce mode scenario against running ocisim servers
    with running_server_on_port(
        enforce_p,
        tmpl_dir,
        persistent=False,
        subcommand='serve',
        extra_args=['--auth', 'enforce', '--auth-config', str(auth_cfg_file)],
    ):
        full = subprocess.run(
            lms_cmd_prefix + ['--no-preflight', lms_file, 'full', str(tmpl_dir), lmoci_bin, str(open_p), str(enforce_p)],
            env=lms_env,
            cwd=tmpl_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert full.returncode == 0, (full.returncode, full.stdout, full.stderr)
        summary = json.loads(full.stdout.strip().splitlines()[-1])
        assert summary.get('ok') is True and summary.get('quote_unicode_verified') is True, summary
    return Path(lmscript_bin).name


lmoci_bin = ensure_lmoci_binary()
checks.append(f'pinned lmoci {LMOCI_VERSION} SHA-256 verified ({Path(lmoci_bin).name})')

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

        list_b_body, _ = request('GET', f'/n/{ns}/b/?compartmentId={urllib.parse.quote(TENANCY)}')
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

        # 7. Open-mode lmoci round trip (and optional oci-cli when installed)
        run_lmoci_roundtrip(lmoci_bin, directory, cred_env=None, prefix='open')
        checks.append('lmoci open-mode full round trip (OS, IAM, Queue)')
        lms_used = run_template_lms_checks(lmoci_bin, directory)
        if lms_used:
            checks.append(f'examples/templates.lms _json_ + expand() open & enforce round trip ({lms_used})')
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

    # 10. Enforced Auth + IAM Policy Matrix (--auth enforce --auth-config ...)
    admin_priv, _, _, admin_pub_pem = generate_rsa_keypair(directory, 'admin')
    reader_priv, _, _, reader_pub_pem = generate_rsa_keypair(directory, 'reader')
    scoped_priv, _, _, scoped_pub_pem = generate_rsa_keypair(directory, 'scoped')
    wildcard_priv, _, _, wildcard_pub_pem = generate_rsa_keypair(directory, 'wildcard')
    wrong_priv, _, _, _ = generate_rsa_keypair(directory, 'wrong')

    admin_user = 'ocid1.user.oc1..adminuser0000000000000000000000000000000000000000000000'
    reader_user = 'ocid1.user.oc1..readeruser000000000000000000000000000000000000000000000'
    scoped_user = 'ocid1.user.oc1..scopeduser000000000000000000000000000000000000000000000'
    wildcard_user = 'ocid1.user.oc1..wildcarduser0000000000000000000000000000000000000000000'

    admin_fp = '11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11'
    reader_fp = '22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22'
    scoped_fp = '33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33'
    wildcard_fp = '44:44:44:44:44:44:44:44:44:44:44:44:44:44:44:44'

    admin_key_id = f'{TENANCY}/{admin_user}/{admin_fp}'
    reader_key_id = f'{TENANCY}/{reader_user}/{reader_fp}'
    scoped_key_id = f'{TENANCY}/{scoped_user}/{scoped_fp}'
    wildcard_key_id = f'{TENANCY}/{wildcard_user}/{wildcard_fp}'

    auth_config_path = directory / 'auth-config.json'
    auth_config_path.write_text(
        json.dumps(
            {
                'credentials': [
                    {
                        'keyId': admin_key_id,
                        'publicKeyPem': admin_pub_pem,
                        'groups': ['Administrators'],
                    },
                    {
                        'keyId': reader_key_id,
                        'publicKeyPem': reader_pub_pem,
                        'groups': ['ObjectReaders'],
                        'statements': [
                            'Allow group ObjectReaders to read object-family in tenancy',
                        ],
                    },
                    {
                        'keyId': scoped_key_id,
                        'publicKeyPem': scoped_pub_pem,
                        'groups': ['ScopedAdmins'],
                        'statements': [
                            'Allow group ScopedAdmins to manage object-family in tenancy',
                            "Deny group ScopedAdmins to manage buckets in tenancy where target.bucket.name = 'protected-*'",
                        ],
                        'policy': {
                            'Version': '2026-01-01',
                            'Statement': [
                                {
                                    'Effect': 'Deny',
                                    'Action': 'oci:os:Delete*',
                                    'Resource': '*',
                                }
                            ],
                        },
                    },
                    {
                        'keyId': wildcard_key_id,
                        'publicKeyPem': wildcard_pub_pem,
                        'policy': {
                            'Version': '2026-01-01',
                            'Statement': [
                                {
                                    'Effect': 'Allow',
                                    'Action': [
                                        'oci:os:Get*',
                                        'oci:os:Head*',
                                        'oci:os:List*',
                                        'oci:os:CreateBucket',
                                        'oci:os:PutObject',
                                        'oci:os:Delete*',
                                    ],
                                    'Resource': [
                                        'namespace:*',
                                        'bucket:allowed-*',
                                        'bucket:allowed-*/object:report-??.txt',
                                    ],
                                }
                            ],
                        },
                    },
                ],
                'policies': [
                    'Allow group Administrators to manage all-resources in tenancy',
                ],
            },
            indent=2,
        ),
        encoding='utf-8',
    )

    with running_server(
        directory,
        persistent=False,
        subcommand='serve',
        extra_args=['--auth', 'enforce', '--auth-config', str(auth_config_path)],
    ):
        # 10a. Health endpoint remains accessible without credentials
        health_body, _ = request('GET', '/_floci-oci/health', include_auth=False, status=200)
        assert json.loads(health_body).get('edition') == 'community'
        checks.append('enforce mode: health endpoint exempt')

        # 10b. Missing credentials -> 401 NotAuthenticated
        no_auth_body, _ = request('GET', '/n/', include_auth=False, status=401)
        no_auth_err = json.loads(no_auth_body)
        assert no_auth_err['code'] == 'NotAuthenticated', no_auth_err
        checks.append('enforce mode: no credentials -> 401 NotAuthenticated')

        # 10c. Unknown keyId / dummy signature -> 401 NotAuthenticated
        bad_key_body, _ = request('GET', '/n/', include_auth=True, status=401)
        assert json.loads(bad_key_body)['code'] == 'NotAuthenticated'
        checks.append('enforce mode: unknown keyId -> 401 NotAuthenticated')

        # 10d. Valid keyId signed with wrong RSA private key -> 401 NotAuthenticated
        wrong_sig_body, _ = signed_request(directory, 'GET', '/n/', admin_key_id, wrong_priv, status=401)
        assert json.loads(wrong_sig_body)['code'] == 'NotAuthenticated'
        # Also verify via lmoci client (exits 3 with NotAuthenticated and no key leak)
        wrong_lmoci_err = invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'namespace'],
            cred_env={
                'LMOCI_TENANCY': TENANCY,
                'LMOCI_USER': admin_user,
                'LMOCI_FINGERPRINT': admin_fp,
                'LMOCI_PRIVATE_KEY_FILE': str(wrong_priv),
            },
            expect_code=3,
        )
        assert 'HTTP 401' in wrong_lmoci_err['message'] and 'NotAuthenticated' in wrong_lmoci_err['message'], wrong_lmoci_err
        checks.append('enforce mode: wrong RSA key / bad signature -> 401 NotAuthenticated (HTTP + lmoci exit 3)')

        # 10e. Tampered request body (x-content-sha256 mismatch) -> 401 NotAuthenticated
        tamper_body, _ = signed_request(
            directory,
            'POST',
            '/n/floci-local/b/',
            admin_key_id,
            admin_priv,
            body={'name': 'legit-bucket', 'compartmentId': TENANCY},
            tamper_body=json.dumps({'name': 'tampered-bucket', 'compartmentId': TENANCY}).encode('utf-8'),
            status=401,
        )
        assert json.loads(tamper_body)['code'] == 'NotAuthenticated'
        checks.append('enforce mode: tampered body x-content-sha256 mismatch -> 401 NotAuthenticated')

        # 10f. Full lmoci round-trip in enforce mode with valid admin RSA key + Allow policy
        admin_env = {
            'LMOCI_TENANCY': TENANCY,
            'LMOCI_USER': admin_user,
            'LMOCI_FINGERPRINT': admin_fp,
            'LMOCI_PRIVATE_KEY_FILE': str(admin_priv),
        }
        run_lmoci_roundtrip(lmoci_bin, directory, cred_env=admin_env, prefix='enforce')
        checks.append('enforce mode: lmoci full round trip with RSA signature + IAM policy')

        # Seed a bucket + object as admin so reader can test read vs write
        invoke_lmoci(lmoci_bin, directory, ['os', 'create-bucket', 'shared-docs'], cred_env=admin_env)
        invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'put-object', 'shared-docs', 'readme.txt', '--content', 'hello-readers'],
            cred_env=admin_env,
        )

        # 10g. Reader policy: allowed read operations succeed; write/manage and other services fail with 403 NotAuthorizedOrNotFound
        reader_env = {
            'LMOCI_TENANCY': TENANCY,
            'LMOCI_USER': reader_user,
            'LMOCI_FINGERPRINT': reader_fp,
            'LMOCI_PRIVATE_KEY_FILE': str(reader_priv),
        }
        assert invoke_lmoci(lmoci_bin, directory, ['os', 'namespace'], cred_env=reader_env)['namespace'] == 'floci-local'
        assert invoke_lmoci(lmoci_bin, directory, ['os', 'head-bucket', 'shared-docs'], cred_env=reader_env)['exists'] is True
        assert invoke_lmoci(lmoci_bin, directory, ['os', 'get-object', 'shared-docs', 'readme.txt'], cred_env=reader_env)['content'] == 'hello-readers'
        assert invoke_lmoci(lmoci_bin, directory, ['os', 'list-objects', 'shared-docs'], cred_env=reader_env)['count'] == 1

        denied_put = invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'put-object', 'shared-docs', 'hack.txt', '--content', 'nope'],
            cred_env=reader_env,
            expect_code=3,
        )
        assert 'HTTP 403' in denied_put['message'] and 'NotAuthorizedOrNotFound' in denied_put['message'], denied_put

        denied_create_bkt = invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'create-bucket', 'reader-bucket'],
            cred_env=reader_env,
            expect_code=3,
        )
        assert 'HTTP 403' in denied_create_bkt['message'] and 'NotAuthorizedOrNotFound' in denied_create_bkt['message'], denied_create_bkt

        denied_queue = invoke_lmoci(
            lmoci_bin,
            directory,
            ['queue', 'create', 'reader-queue'],
            cred_env=reader_env,
            expect_code=3,
        )
        assert 'HTTP 403' in denied_queue['message'] and 'NotAuthorizedOrNotFound' in denied_queue['message'], denied_queue
        checks.append('enforce mode: reader policy allows Get/Head/List and denies Put/Create/Queue (403 NotAuthorizedOrNotFound)')

        # 10h. Explicit Deny overrides Allow (both JSON Action glob Deny and OCI IAM where-clause Deny)
        scoped_env = {
            'LMOCI_TENANCY': TENANCY,
            'LMOCI_USER': scoped_user,
            'LMOCI_FINGERPRINT': scoped_fp,
            'LMOCI_PRIVATE_KEY_FILE': str(scoped_priv),
        }
        invoke_lmoci(lmoci_bin, directory, ['os', 'create-bucket', 'scoped-work'], cred_env=scoped_env)
        invoke_lmoci(lmoci_bin, directory, ['os', 'put-object', 'scoped-work', 'item.txt', '--content', 'data'], cred_env=scoped_env)
        assert invoke_lmoci(lmoci_bin, directory, ['os', 'get-object', 'scoped-work', 'item.txt'], cred_env=scoped_env)['content'] == 'data'

        # Explicit Deny on oci:os:Delete* overrides Allow manage object-family
        deny_del_obj = invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'delete-object', 'scoped-work', 'item.txt'],
            cred_env=scoped_env,
            expect_code=3,
        )
        assert 'HTTP 403' in deny_del_obj['message'] and 'NotAuthorizedOrNotFound' in deny_del_obj['message'], deny_del_obj

        deny_del_bkt = invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'delete-bucket', 'scoped-work'],
            cred_env=scoped_env,
            expect_code=3,
        )
        assert 'HTTP 403' in deny_del_bkt['message'] and 'NotAuthorizedOrNotFound' in deny_del_bkt['message'], deny_del_bkt

        # Explicit Deny where target.bucket.name = 'protected-*' overrides Allow manage object-family
        deny_prot_bkt = invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'create-bucket', 'protected-audit'],
            cred_env=scoped_env,
            expect_code=3,
        )
        assert 'HTTP 403' in deny_prot_bkt['message'] and 'NotAuthorizedOrNotFound' in deny_prot_bkt['message'], deny_prot_bkt
        checks.append('enforce mode: explicit Deny overrides Allow (action glob and target.bucket.name condition)')

        # 10i. Wildcard matching (* and ?) on Action and Resource
        wildcard_env = {
            'LMOCI_TENANCY': TENANCY,
            'LMOCI_USER': wildcard_user,
            'LMOCI_FINGERPRINT': wildcard_fp,
            'LMOCI_PRIVATE_KEY_FILE': str(wildcard_priv),
        }
        invoke_lmoci(lmoci_bin, directory, ['os', 'create-bucket', 'allowed-reports'], cred_env=wildcard_env)
        invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'put-object', 'allowed-reports', 'report-01.txt', '--content', 'q1-report'],
            cred_env=wildcard_env,
        )
        assert invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'get-object', 'allowed-reports', 'report-01.txt'],
            cred_env=wildcard_env,
        )['content'] == 'q1-report'

        # Bucket outside 'bucket:allowed-*' is denied
        deny_wild_bkt = invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'create-bucket', 'forbidden-reports'],
            cred_env=wildcard_env,
            expect_code=3,
        )
        assert 'HTTP 403' in deny_wild_bkt['message'] and 'NotAuthorizedOrNotFound' in deny_wild_bkt['message'], deny_wild_bkt

        # Object outside 'bucket:allowed-*/object:report-??.txt' is denied
        deny_wild_obj = invoke_lmoci(
            lmoci_bin,
            directory,
            ['os', 'put-object', 'allowed-reports', 'report-2026.txt', '--content', 'too-long-for-two-char-wildcard'],
            cred_env=wildcard_env,
            expect_code=3,
        )
        assert 'HTTP 403' in deny_wild_obj['message'] and 'NotAuthorizedOrNotFound' in deny_wild_obj['message'], deny_wild_obj
        checks.append('enforce mode: wildcard (* and ?) matching on Action and Resource')

print(json.dumps({'ok': True, 'checks': checks, 'leftovers': 0}, indent=2))

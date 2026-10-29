#!/usr/bin/env python3
"""Verify pinned floci-oci source, apply our CLI overlay, build on this host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--jvm', action='store_true', help='build fast JVM quarkus-app instead of native binary')
parser.add_argument('--native', action='store_true', help='build native executable (default)')
parser.add_argument('--offline', action='store_true', help='require cached source archive and Maven offline mode')
args = parser.parse_args()

ROOT = Path(__file__).resolve().parents[1]
lock = json.loads((ROOT / 'upstream.lock.json').read_text(encoding='utf-8'))
cache = ROOT / '.cache'
cache.mkdir(exist_ok=True)
archive = cache / 'floci-oci.tar.gz'
if not archive.exists():
    if args.offline:
        sys.exit('offline: cached archive .cache/floci-oci.tar.gz is missing')
    url = f"https://codeload.github.com/floci-io/floci-oci/tar.gz/{lock['commit']}"
    with urllib.request.urlopen(url, timeout=120) as response:
        archive.write_bytes(response.read())
if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['sha256']:
    sys.exit('floci-oci source checksum mismatch; remove .cache/floci-oci.tar.gz and retry')

source = ROOT / 'build' / 'upstream'
if not source.exists():
    source.parent.mkdir(exist_ok=True)
    with tarfile.open(archive) as tar:
        tar.extractall(source.parent, filter='data')
    (source.parent / f"floci-oci-{lock['commit']}").rename(source)

for path in (ROOT / 'src').rglob('*.java'):
    target = source / path.relative_to(ROOT)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        path.read_text(encoding='utf-8')
        .replace('@VERSION@', (ROOT / 'VERSION').read_text(encoding='utf-8').strip())
        .replace('@UPSTREAM@', lock['tag']),
        encoding='utf-8',
    )

# docker-java's Unix domain socket initializer resolves libc symbols via JNA,
# which do not exist on Windows. Defer this unused transport to runtime.
metadata = source / 'src/main/resources/META-INF/native-image/ai.lmctl/ocisim/native-image.properties'
metadata.parent.mkdir(parents=True, exist_ok=True)
metadata.write_text(
    'Args = --initialize-at-run-time=com.github.dockerjava.transport.DomainSocket\n',
    encoding='utf-8',
)

env = os.environ.copy()
env.setdefault('MEMGUARD_MIN_MB', '500')
fallback_graal = Path('/tmp/graalvm-community-openjdk-25.0.2+10.1')
if fallback_graal.is_dir() and '25' not in env.get('JAVA_HOME', ''):
    env['JAVA_HOME'] = str(fallback_graal)
    env['PATH'] = str(fallback_graal / 'bin') + os.pathsep + env.get('PATH', '')

command = [
    shutil.which('mvn.cmd' if os.name == 'nt' else 'mvn', path=env.get('PATH')) or ('mvn.cmd' if os.name == 'nt' else 'mvn'),
    '-B',
    '-q',
    'package',
    '-Dmaven.test.skip=true',
    '-Dcheckstyle.skip=true',
    '-Dquarkus.package.main-class=ai.lmctl.ocisim.Main',
]
if args.offline:
    command.append('-o')
if not args.jvm:
    command += [
        '-Dnative',
        '-Dquarkus.native.native-image-xmx=' + os.getenv('NATIVE_XMX', '4g'),
        '-Dquarkus.native.additional-build-args-append=-Ob,-march=compatibility',
    ]
subprocess.run(command, cwd=source, env=env, check=True)
dist = ROOT / 'dist'
dist.mkdir(exist_ok=True)
if not args.jvm:
    suffix = '.exe' if os.name == 'nt' else ''
    output = dist / ('ocisim' + suffix)
    shutil.copy2(source / 'target' / ('floci-oci-' + lock['tag'] + '-runner' + suffix), output)
    print(output)
else:
    shutil.copytree(source / 'target' / 'quarkus-app', dist / 'quarkus-app', dirs_exist_ok=True)
    print(dist / 'quarkus-app' / 'quarkus-run.jar')

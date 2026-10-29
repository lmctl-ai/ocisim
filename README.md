# ocisim

Local Oracle Cloud Infrastructure (OCI) emulator on `127.0.0.1:4599`, built on
[floci-oci](https://github.com/floci-io/floci-oci). Packaged as one standalone
native executable. Object Storage, Identity (IAM), Queue, Streaming, Vault, KMS,
and Secrets run in-process without requiring Java, Docker, or an Oracle Cloud
account at runtime.

## Quickstart

```sh
ocisim --version
ocisim serve
```

In another terminal, use the official OCI CLI (with any locally generated RSA
key; signatures are parsed for tenancy isolation and never verified) or any OCI
SDK pointed at `http://127.0.0.1:4599`:

```sh
# Health check
curl http://127.0.0.1:4599/_floci-oci/health

# With OCI CLI configured against default tenancy:
# tenancy=ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000
oci os ns get --endpoint http://127.0.0.1:4599
oci os bucket create --endpoint http://127.0.0.1:4599 \
  --compartment-id ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000 \
  --namespace-name floci-local --name demo-bucket
```

`start` is an alias for foreground `serve`; stop with Ctrl-C. Use `--port 4600`
to choose another port, or `--data-dir ./state` to persist state across restarts.
Without `--data-dir`, storage is in memory. The HTTP listener binds `127.0.0.1`
only. Docker-backed services (`functions`, `oke`) default to mock mode (`mock=true`)
so no Docker daemon is needed unless explicitly enabled via
`FLOCI_OCI_SERVICES_FUNCTIONS_MOCK=false` or `FLOCI_OCI_SERVICES_OKE_MOCK=false`.

## Build and test

Requires Python 3.12+, Maven 3.9+, and GraalVM JDK 25 (`native-image` on `PATH`).

```sh
python3 scripts/build.py
python3 scripts/test-cli.py dist/ocisim
python3 scripts/test-integration.py dist/ocisim
```

For fast JVM iteration during development:

```sh
python3 scripts/build.py --jvm
python3 scripts/test-cli.py dist/quarkus-app/quarkus-run.jar
python3 scripts/test-integration.py dist/quarkus-app/quarkus-run.jar
```

`scripts/build.py` downloads the pinned `floci-oci` source tarball once into
`.cache/floci-oci.tar.gz` and verifies its SHA-256 digest against
`upstream.lock.json` on every run. Pass `--offline` once cached to build
without network access.

`scripts/test-integration.py` runs offline against an ephemeral `ocisim`
process on an OS-assigned loopback port. It verifies:
- Occupied-port startup failure (exit code `3` with JSON error envelope)
- Health endpoint (`GET /_floci-oci/health`)
- Object Storage namespace, bucket create/get/list, binary object put/head/get/list/rename, and metadata preservation
- Multi-tenancy storage isolation driven by the OCI `Authorization: Signature` `keyId` tenancy OCID
- Identity (IAM) regions and compartment creation/listing
- Queue creation, work-request header, message put/get/delete, and queue deletion
- Official `oci` CLI (`oci os`, `oci iam`) round trip when `oci` is installed on `PATH`
- State persistence across process restart (`start --data-dir`) and ephemeral memory cleanup

### Client handoff (`lmoci`)

`lmoci` (`github.com/lmctl-ai/lmoci`) is the sibling native OCI SDK client for
`lmscript`. Point `lmoci` (or any OCI SDK/CLI) at `http://127.0.0.1:4599` with:
- Default tenancy OCID: `ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000`
- Default user OCID: `ocid1.user.oc1..flocilocaluser00000000000000000000000000000000000000000000`
- Default namespace: `floci-local`
- Default region: `us-ashburn-1`

## Design decisions

- **Pinned upstream source + thin CLI overlay**: `upstream.lock.json` pins
  `floci-io/floci-oci` tag `0.5.0` by immutable Git commit and source tarball
  SHA-256. Upstream publishes Docker images on release rather than standalone
  native binaries or Maven Central JARs, so `scripts/build.py` stages the
  verified upstream source under gitignored `build/upstream`, overlays
  `src/main/java/ai/lmctl/ocisim/Main.java` (`@QuarkusMain`), and compiles a
  single native executable retaining upstream's GraalVM reachability metadata
  and BouncyCastle crypto registrations.
- **CLI contract**: Exit code `0` for `--version`, `--help`, and clean server
  shutdown; `2` for invalid CLI usage; `3` for server startup/runtime failure.
  CLI errors emit `{"ok":false,"error":{"kind":"usage|runtime","message":"..."}}`
  on stdout while server logs go to stderr.
- **Safe local defaults**: Loopback-only binding (`127.0.0.1`), TLS disabled by
  default, in-memory storage unless `--data-dir` is passed, and Docker sidecars
  (`functions`, `oke`) defaulted to mock mode.

## License

MIT (`LICENSE`). Upstream attribution is preserved in `FLOCI-LICENSE`.

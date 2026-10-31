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

In another terminal, use [`lmoci`](https://github.com/lmctl-ai/lmoci), the
official OCI CLI, or any OCI SDK pointed at `http://127.0.0.1:4599`:

```sh
# Health check
curl http://127.0.0.1:4599/_floci-oci/health

# With lmoci (open mode uses default local tenancy/user automatically):
lmoci os namespace --endpoint http://127.0.0.1:4599
lmoci os create-bucket demo-bucket --endpoint http://127.0.0.1:4599
lmoci os put-object demo-bucket hello.txt --content "hello from lmoci" --endpoint http://127.0.0.1:4599
lmoci os get-object demo-bucket hello.txt --endpoint http://127.0.0.1:4599
```

`start` is an alias for foreground `serve`; stop with Ctrl-C. Use `--port 4600`
to choose another port, or `--data-dir ./state` to persist state across restarts.
Without `--data-dir`, storage is in memory. The HTTP listener binds `127.0.0.1`
only. Docker-backed services (`functions`, `oke`) default to mock mode (`mock=true`)
so no Docker daemon is needed unless explicitly enabled via
`FLOCI_OCI_SERVICES_FUNCTIONS_MOCK=false` or `FLOCI_OCI_SERVICES_OKE_MOCK=false`.

## Authentication and IAM Permissions (`--auth enforce`)

By default, `ocisim` runs in `--auth open` mode: it parses the `keyId` from OCI
`Authorization: Signature` headers for multi-tenancy storage isolation without
verifying RSA signatures or enforcing IAM policies.

Pass `--auth enforce --auth-config auth.json` (or set `OCISIM_AUTH=enforce` /
`SIM_AUTH=enforce` and `OCISIM_AUTH_CONFIG=auth.json` / `SIM_AUTH_CONFIG=auth.json`)
to enable full two-layer enforcement:

1. **Layer 1 — Authentication (`401 NotAuthenticated`)**:
   - Verifies draft-cavage OCI HTTP signatures (`Authorization: Signature version="1",keyId="<tenancy>/<user>/<fingerprint>",algorithm="rsa-sha256",headers="...",signature="<base64>"`) against the caller's configured 2048-bit RSA public key.
   - Verifies `x-content-sha256` against the SHA-256 digest of the request body whenever signed.
   - Rejects missing credentials, unknown `keyId`s, tampered bodies, or invalid RSA-SHA256 signatures with HTTP `401` JSON `{"code": "NotAuthenticated", "message": "The required information to complete authentication was not provided or was incorrect."}`.
2. **Layer 2 — IAM Policy Enforcement (`403 NotAuthorizedOrNotFound`)**:
   - Evaluates both OCI IAM policy statements (`Allow|Deny group <G> to <inspect|read|use|manage> <resource-family> in tenancy|compartment <C> [where ...]`) and JSON policy statements (`Statement[{Effect, Action, Resource}]`).
   - Enforces **default-deny** whenever policies are present, **explicit `Deny` overrides `Allow`**, and **wildcard matching** (`*`, `?`) on actions, verbs, resource types/families, and resource identifiers.
   - Rejects denied operations with HTTP `403` JSON `{"code": "NotAuthorizedOrNotFound", "message": "Authorization failed or requested resource not found."}`. Emitting `403` (rather than `404`) ensures idempotent SDK/CLI probes such as `HeadBucket`, `HeadObject`, and `Delete*` surface `BmcException(403, "NotAuthorizedOrNotFound")` instead of misinterpreting a permission denial as `exists: false` or `deleted: true`.

### Example `auth.json` and `lmoci` Enforced Workflow

```json
{
  "credentials": [
    {
      "keyId": "ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000/ocid1.user.oc1..flocilocaluser00000000000000000000000000000000000000000000/11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00",
      "publicKeyFile": "./user-public.pem",
      "groups": ["ObjectWriters"],
      "statements": [
        "Allow group ObjectWriters to manage object-family in tenancy",
        "Deny group ObjectWriters to manage buckets in tenancy where target.bucket.name = 'protected-*'"
      ],
      "policy": {
        "Version": "2026-01-01",
        "Statement": [
          {
            "Effect": "Deny",
            "Action": "oci:os:DeleteBucket",
            "Resource": "*"
          }
        ]
      }
    }
  ]
}
```

Start `ocisim` in enforced mode and invoke via `lmoci`:

```sh
ocisim serve --auth enforce --auth-config ./auth.json

export LMOCI_TENANCY="ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000"
export LMOCI_USER="ocid1.user.oc1..flocilocaluser00000000000000000000000000000000000000000000"
export LMOCI_FINGERPRINT="11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"
export LMOCI_PRIVATE_KEY_FILE="./user-private.pem"

# Allowed by policy (exits 0):
lmoci os create-bucket app-data --endpoint http://127.0.0.1:4599
lmoci os put-object app-data hello.txt --content "signed payload" --endpoint http://127.0.0.1:4599

# Denied by explicit Deny statement (exits 3 with HTTP 403 NotAuthorizedOrNotFound):
lmoci os delete-bucket app-data --endpoint http://127.0.0.1:4599
```

## Template-Driven `.lms` Integration (`examples/templates.lms`)

[`examples/templates.lms`](examples/templates.lms) demonstrates template-driven
`lmscript` + `lmoci` integration against `ocisim` in both `--auth open` and
`--auth enforce` modes:

- **JSON templates (`_json_` blocks)**:
  - Authors the `--auth-config` JSON document (`credentials`, `groups`,
    `statements`, `policy.Statement`) with typed context variables (`${expr}`
    standalone for arrays/objects/numbers, `${expr}` inside strings with
    automatic JSON string escaping) and writes it via `write_json(...)`.
  - Authors structured Object Storage and Queue event JSON payloads containing
    quotes (`"`) and Unicode (`"OCI \"Quoted\" Pipeline — 雪 / 🚀"`).
- **Non-JSON text templates (`expand()`)**:
  - Expands URLs, Object Storage hierarchy keys (`tenants/${tenant_slug}/...`),
    OCI `keyId`s (`${tenancy_id}/${user_id}/${fingerprint}`), and OCI IAM policy
    statements (`Allow group ${writer_group} to manage ...`).
- **Typed `_dsl_` + CLI verification**:
  - Compiles and executes an embedded `_dsl_` program via `lmoci --lmcode` driving
    5 representative OCI workflows (IAM compartment + policy analysis, bucket
    creation, JSON object put/get/list/rename, Queue message put/receive/delete,
    and run ledger cleanup).
  - Exercises both `--auth open` and `--auth enforce`, verifying allowed writes,
    allowed reads, `403 NotAuthorizedOrNotFound` policy denials, and `401
    NotAuthenticated` signature failures.

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

`scripts/test-integration.py` downloads and SHA-256-verifies the pinned
`lmctl-ai/lmoci` `v0.1.0` release binary for the host platform and runs offline
against `ocisim` on an OS-assigned loopback port. It verifies:
- Occupied-port startup failure (exit code `3` with JSON error envelope)
- Health endpoint (`GET /_floci-oci/health`) in both open and enforce modes
- Object Storage namespace, bucket create/get/list, binary object put/head/get/list/rename, and metadata preservation
- Multi-tenancy storage isolation driven by the OCI `Authorization: Signature` `keyId` tenancy OCID
- Identity (IAM) regions and compartment creation/listing
- Queue creation, work-request header, message put/get/delete, and queue deletion
- Full `lmoci` end-to-end round-trip (`os`, `iam`, `queue`) in both `--auth open` and `--auth enforce` modes
- Enforced authentication and IAM policy test matrix: missing credentials (`401`), unknown `keyId` (`401`), wrong RSA private key (`401`), tampered body `x-content-sha256` (`401`), read-only policy default-deny on writes (`403`), explicit `Deny` overriding `Allow` (`403`), and wildcard (`*`, `?`) action/resource matching
- State persistence across process restart (`start --data-dir`) and ephemeral memory cleanup

Default emulator identity:
- Default tenancy OCID: `ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000`
- Default user OCID: `ocid1.user.oc1..flocilocaluser00000000000000000000000000000000000000000000`
- Default namespace: `floci-local`
- Default region: `us-ashburn-1`

## Design decisions

- **Pinned upstream source + thin overlay**: `upstream.lock.json` pins
  `floci-io/floci-oci` tag `0.5.0` by immutable Git commit and source tarball
  SHA-256. `scripts/build.py` stages the verified upstream source under
  gitignored `build/upstream`, overlays `src/main/java/ai/lmctl/ocisim/`
  (`Main`, `AuthConfig`, `OciAuthFilter`, `OciPolicyEngine`), and compiles a
  single native executable retaining upstream's GraalVM reachability metadata
  and BouncyCastle crypto registrations.
- **CLI contract**: Exit code `0` for `--version`, `--help`, and clean server
  shutdown; `2` for invalid CLI usage or unreadable/invalid `--auth-config`;
  `3` for server startup/runtime failure. CLI errors emit
  `{"ok":false,"error":{"kind":"usage|runtime","message":"..."}}` on stdout
  while server logs go to stderr.
- **Safe local defaults**: Loopback-only binding (`127.0.0.1`), TLS disabled by
  default, open auth mode unless `--auth enforce` is passed, in-memory storage
  unless `--data-dir` is passed, and Docker sidecars (`functions`, `oke`)
  defaulted to mock mode.

## License

MIT (`LICENSE`). Upstream attribution is preserved in `FLOCI-LICENSE`.

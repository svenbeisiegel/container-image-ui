# container-ui

A zero-dependency, Node.js web UI for managing container images. Supports three backends: a remote container registry (via **skopeo**), **docker**, and **crictl**.

## Features

- List all images with name, tag, digest, and size.
- Per-image actions: **Details**, **Delete**, **Download**, **Pull**, **Verify**.
- Multi-select with bulk **Delete**, **Download**, and **Verify**.
- **Upload** images from a `.tar`, `.tar.gz`/`.tgz`, or `.tar.xz` archive.
- **Pull** an image reference into the active backend.
- Downloads are streamed and compressed as `.tar.xz`.
- **Signature verification**: Ed25519 / X.509 image signatures validated in the browser with real-time status indicators.
- DNS-rebinding and CSRF protection (Host/Origin header validation).
- Debug logging via `DEBUG=1`.

## Requirements

**Always required:**

- **Node.js >= 24**
- `tar`, `xz`, and `gzip` on `PATH`

**Backend-specific requirements** (one of the following):

| Backend | Required binaries | Notes |
|---------|------------------|-------|
| Registry | `skopeo` | Hard requirement. `REGISTRY_URL` must be set and reachable. |
| Docker | `docker` | All features available. |
| crictl | `crictl` | List/inspect/delete/verify always work. Download/upload additionally require `ctr` (containerd). |

The tool detects prerequisites at startup and exits with a descriptive error if a hard requirement is missing.

## Quick start

```sh
npm start
```

Open http://127.0.0.1:3000.

## Configuration

All configuration is through environment variables.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Listening port. |
| `HOST` | `127.0.0.1` | Bind address. |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1],::1,<HOST>` | Comma-separated list of permitted Host header values. Override when accessing the UI from a non-localhost address. |
| `DEBUG` / `LOG_LEVEL` | — | Set to `1`, `true`, or `debug` to enable verbose debug output on stderr. |

### Signature verification

| Variable | Default | Description |
|----------|---------|-------------|
| `ROOT_CA_PATH` | — | Path to a PEM-encoded root CA certificate used as the trust anchor for image signature verification. Falls back to the embedded CA when unset. |
| `SIGN_LABEL_PREFIX` | `org.mitel.imagesign` | Reverse-DNS prefix of the OCI labels carrying the signature and certificate chain. |

### Remote registry backend

Set `REGISTRY_URL` to a reachable registry to activate the registry backend. It takes precedence over docker/crictl. **`skopeo` must be installed.**

| Variable | Required | Description |
|----------|----------|-------------|
| `REGISTRY_URL` | to enable | Registry base URL, e.g. `https://registry.example.com:5000`. Must be `http://` or `https://`. |
| `REGISTRY_USERNAME` | optional | Username for HTTP Basic authentication. |
| `REGISTRY_PASSWORD` | optional | Password for HTTP Basic authentication. |
| `REGISTRY_CA_PATH` | optional | Path to a PEM CA bundle for a self-signed registry TLS certificate. |
| `REGISTRY_INSECURE` | optional | Set to `1` to skip TLS verification for the registry. |

Credentials are never passed on the skopeo command line. At startup they are written to a `0600` auth file in a private temp directory and exposed to child processes via `REGISTRY_AUTH_FILE`.

When `REGISTRY_URL` is set but the registry is unreachable or `skopeo` is missing, the server logs a warning and falls back to the next available local engine (docker or crictl).

## Backend selection order

1. **Registry** — when `REGISTRY_URL` is set, reachable (`GET /v2/` returns 200), and `skopeo` is installed.
2. **Docker** — when `docker` is found on `PATH`.
3. **crictl** — when `crictl` is found on `PATH`.

The active backend is logged at startup, e.g.:

```
Container engine: registry (https://registry.example.com:5000) via skopeo
Container engine: docker
Container engine: crictl
```

## Feature availability per backend

| Feature | Registry | Docker | crictl |
|---------|----------|--------|--------|
| List images | ✓ | ✓ | ✓ |
| Details / inspect | ✓ | ✓ | ✓ |
| Delete | ✓ | ✓ | ✓ |
| Signature verify | ✓ | ✓ | ✓ |
| Pull | ✓ (skopeo copy) | ✓ | ✓ |
| Download | ✓ (OCI layout tar.xz) | ✓ | ✓ with `ctr` |
| Upload | ✓ (skopeo copy) | ✓ | ✓ with `ctr` |

## Download / upload archive format

### Docker / crictl backend

Archives are standard `docker save` tarballs, compressed with xz. They can be loaded with `docker load` or `ctr images import`.

### Registry backend

Archives use the **OCI image layout** format, tar'd and xz-compressed. Each image is stored as `img0`, `img1`, … entries. A `refs.json` sidecar maps each slot back to its original registry reference so that upload restores the images under their original paths.

Archives produced by this tool can be pushed back to the same (or another) registry via the Upload function. Standard `docker save` archives can also be uploaded; the tool detects the archive type automatically.

## Image signing

The tooling uses **Ed25519** signatures embedded as OCI config labels. Two shell scripts are provided.

### `image-sign.sh`

Signs an image's layer set with an X.509 key from a PKCS#12 container and writes the signature + certificate chain back as image labels **without adding a filesystem layer** (layer hashes are unchanged).

```sh
./image-sign.sh -s <src-image> -d <dest-image> -p <signer.p12> [-r <label-prefix>] [-n <ctr-ns>]
```

| Flag | Description |
|------|-------------|
| `-s` | Source image reference (as it appears in docker/ctr/buildah). |
| `-d` | Destination image reference for the signed result. |
| `-p` | PKCS#12 file containing the private key + leaf certificate + intermediate CA. |
| `-r` | Label prefix (default: `org.mitel.imagesign`). |
| `-n` | containerd namespace (default: `k8s.io`). |

The PKCS#12 passphrase is read from `$P12_PASSWORD` or prompted interactively.

**Required tools:** `skopeo`, `umoci`, `openssl`, `jq`, `base64`, `sha256sum`.

**Source store auto-detection:** docker → ctr → buildah (first that contains the image).

The signing algorithm:

1. Export the image to an OCI layout.
2. Compute `LAYER_HASH = SHA-256(diff_id_1\ndiff_id_2\n...)` as a 64-char hex string.
3. Sign `LAYER_HASH` with `openssl pkeyutl -sign -rawin`.
4. Attach `<prefix>.signature`, `<prefix>.certchain`, and `<prefix>.alg=ed25519` labels via `umoci config --no-history` (no new layer added, diff_ids unchanged).
5. Import the signed image back into the same store.

### `image-verify.sh`

Verifies a signed image's certificate chain and signature.

```sh
./image-verify.sh -i <image> [-c <root-ca.pem>] [-r <label-prefix>] [-n <ctr-ns>]
```

| Flag | Description |
|------|-------------|
| `-i` | Image reference to verify. |
| `-c` | Root CA PEM file. Falls back to the embedded CA when omitted. |
| `-r` | Label prefix (default: `org.mitel.imagesign`). |
| `-n` | containerd namespace (default: `k8s.io`). |

Exits `0` when both certificate chain and signature checks pass, `1` otherwise.

**Required tools:** `openssl`, `jq`, `base64`, `sha256sum`.

### In-browser verification

The UI's **Verify** button runs the same algorithm as `image-verify.sh` entirely on the server (Node.js `node:crypto`), using the configured root CA or the embedded fallback. Each image gets a colour-coded status dot:

- **Green** — signature valid, chain chains to the trusted CA.
- **Red** — signature invalid or certificate chain broken.
- **Grey** — no signature labels found on the image.

## Project layout

```
server.js           HTTP server, routing, streaming download/upload, SSE.
lib/
  cli.js            Prerequisite checks, engine detection, spawn helpers.
  images.js         List/inspect/delete/export/import per engine, signature verification.
  registry.js       Registry backend: HTTP client (catalog/probe) + skopeo wrapper.
public/
  index.html        UI shell.
  styles.css        Styles.
  app.js            Frontend logic (fetch, SSE, drag-drop, verify).
test/
  images.test.js    Unit tests for image parsing, normalisation, signature verification.
  registry.test.js  Unit tests for registry config, ref parsing, skopeo arg builders.
  server.test.js    Unit tests for server-side helpers (isValidRef, etc.).
image-sign.sh       Sign an image with a PKCS#12 key.
image-verify.sh     Verify a signed image against a root CA.
signing-key.pub.pem Example public key (for development / testing only).
```

## Tests

```sh
npm test
```

Uses Node.js's built-in test runner (`node:test`). No external test dependencies.

## Security notes

- The server has **no authentication**. Bind to a trusted/local address. Use `ALLOWED_HOSTS` when exposing beyond localhost and place an authenticating reverse proxy in front.
- Registry credentials are never passed on the command line (visible via `ps`). They are written to a `0600` temp file and consumed by skopeo via `REGISTRY_AUTH_FILE`.
- All user-supplied image references are validated before being passed to CLI tools: leading `-` and control characters are rejected to prevent argument injection.
- The registry HTTP client caps redirect following at 5 hops and enforces a 15-second request timeout.

## License

MIT

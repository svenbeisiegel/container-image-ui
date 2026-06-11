#!/usr/bin/env bash
#
# verify-image.sh
#
# Verify a container image signature purely from its labels:
#   1. signature  -- recompute LAYER_HASH from the image's own rootfs diff_ids
#                    and verify the label's signature against the public key in
#                    the label's leaf certificate.
#   2. chain      -- verify the label's certificate chain (leaf + intermediates)
#                    against the root CA certificate provided on the command line.
#
# Both checks must pass for an exit code of 0.
#
# Source store is auto-detected: docker -> ctr -> buildah.
#
set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage: $0 -i IMAGE [-c ROOT_CA_PEM] [-r LABEL_PREFIX] [-n CTR_NS]

  -i IMAGE         image reference to verify (as it appears in its store)
  -c ROOT_CA_PEM   root CA certificate (PEM) used as the trust anchor
                   (optional; falls back to the embedded CA if omitted)
  -r LABEL_PREFIX  reverse-DNS label prefix (default: org.mitel.imagesign)
  -n CTR_NS        containerd namespace for ctr
                   (default: \$CONTAINERD_NAMESPACE or "k8s.io")
EOF
  exit 2
}

# Hardcoded fallback CA, used when no -c ROOT_CA_PEM is given on the command
# line. Replace the placeholder below with your internal root CA certificate.
EMBEDDED_CA="$(cat <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBizCCAT2gAwIBAgIEJvSEJzAFBgMrZXAwTDELMAkGA1UEBhMCREUxDjAMBgNV
BAoTBU1pdGVsMRQwEgYDVQQLEwtEZXZlbG9wbWVudDEXMBUGA1UEAxMOb2NpLXNp
Z25pbmctY2EwIBcNMjYwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMEwxCzAJ
BgNVBAYTAkRFMQ4wDAYDVQQKEwVNaXRlbDEUMBIGA1UECxMLRGV2ZWxvcG1lbnQx
FzAVBgNVBAMTDm9jaS1zaWduaW5nLWNhMCowBQYDK2VwAyEAl9seyjKY9Z08Q6uF
qGl5wWnhYiK8vqczYZgjWWOwF2mjPzA9MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFH1RavYd2ysqs/WZs+CzCr3m0/jTMAsGA1UdDwQEAwIBBjAFBgMrZXADQQC9
ms9Ru0LNfzrq/RFSXlLlHq0mic5tSPTjYjBDdEa5Euw/LY0QnR2wn3vZMI11Htr0
cjoR4gAFMUect5LoYvIC
-----END CERTIFICATE-----
EOF
)"

LABEL_PREFIX="org.mitel.imagesign"
NS="${CONTAINERD_NAMESPACE:-k8s.}"
IMG=""
ROOT_CA=""

while getopts ":i:c:r:n:h" opt; do
  case "$opt" in
    i) IMG=$OPTARG ;;
    c) ROOT_CA=$OPTARG ;;
    r) LABEL_PREFIX=$OPTARG ;;
    n) NS=$OPTARG ;;
    h) usage ;;
    *) usage ;;
  esac
done

[[ -n $IMG ]] || usage
if [[ -n $ROOT_CA ]]; then
  [[ -r $ROOT_CA ]] || { echo "Cannot read root CA file: $ROOT_CA" >&2; exit 1; }
fi

for bin in openssl jq base64 sha256sum awk grep tr; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Required tool not found: $bin" >&2; exit 1; }
done

### ---- detect the source store -------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }
docker_has()  { docker image inspect "$1" >/dev/null 2>&1; }
ctr_has()     { ctr -n "$NS" images ls -q 2>/dev/null | grep -Fxq "$1"; }
buildah_has() { buildah inspect --type image "$1" >/dev/null 2>&1; }

if   have docker  && docker_has  "$IMG"; then SOURCE=docker
elif have ctr     && ctr_has     "$IMG"; then SOURCE=ctr
elif have buildah && buildah_has "$IMG"; then SOURCE=buildah
else
  echo "Image '$IMG' not found in docker, ctr (namespace '$NS'), or buildah." >&2
  exit 1
fi

### ---- scratch ------------------------------------------------------------

umask 077
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/imgverify.XXXXXX")
trap 'rm -rf "$WORKDIR"' EXIT
LAYOUT="$WORKDIR/layout"; ARC="$WORKDIR/img.tar"
CHAIN_PEM="$WORKDIR/chain.pem"; LEAF_PEM="$WORKDIR/leaf.pem"
INTER_PEM="$WORKDIR/inter.pem"; PUB_PEM="$WORKDIR/pub.pem"
DATA="$WORKDIR/data.bin"; SIG="$WORKDIR/sig.bin"

# Fall back to the embedded CA when none was supplied on the command line.
if [[ -z $ROOT_CA ]]; then
  ROOT_CA="$WORKDIR/embedded-ca.pem"
  printf '%s\n' "$EMBEDDED_CA" > "$ROOT_CA"
  echo "Root CA           : using embedded fallback certificate" >&2
fi

### ---- read diff_ids + labels from the image (store-specific) -------------

oci_config_file() {
  local dir=$1 tag=$2 d mfile cfg
  d=$(jq -r --arg t "$tag" \
        '(.manifests[] | select((.annotations["org.opencontainers.image.ref.name"]//"")==$t) | .digest) // .manifests[0].digest' \
        "$dir/index.json")
  mfile="$dir/blobs/$(printf '%s' "$d" | tr ':' '/')"
  if jq -e '.manifests' "$mfile" >/dev/null 2>&1; then
    d=$(jq -r '.manifests[0].digest' "$mfile")
    mfile="$dir/blobs/$(printf '%s' "$d" | tr ':' '/')"
  fi
  cfg=$(jq -r '.config.digest' "$mfile")
  printf '%s\n' "$dir/blobs/$(printf '%s' "$cfg" | tr ':' '/')"
}

DIFFIDS="" SIG_B64="" CHAIN_B64=""
case "$SOURCE" in
  docker)
    DIFFIDS=$(docker image inspect "$IMG" --format '{{json .RootFS.Layers}}' | jq -r '.[]')
    LBL=$(docker image inspect "$IMG" --format '{{json .Config.Labels}}')
    SIG_B64=$(printf '%s' "$LBL" | jq -r --arg k "${LABEL_PREFIX}.signature" '.[$k] // empty')
    CHAIN_B64=$(printf '%s' "$LBL" | jq -r --arg k "${LABEL_PREFIX}.certchain" '.[$k] // empty')
    ;;
  buildah)
    J=$(buildah inspect --type image "$IMG")
    DIFFIDS=$(printf '%s' "$J" | jq -r '(.OCIv1.rootfs.diff_ids // .Docker.rootfs.diff_ids)[]')
    SIG_B64=$(printf '%s' "$J" | jq -r --arg k "${LABEL_PREFIX}.signature" '(.OCIv1.config.Labels // .Docker.config.Labels)[$k] // empty')
    CHAIN_B64=$(printf '%s' "$J" | jq -r --arg k "${LABEL_PREFIX}.certchain" '(.OCIv1.config.Labels // .Docker.config.Labels)[$k] // empty')
    ;;
  ctr)
    command -v skopeo >/dev/null 2>&1 || { echo "skopeo required for ctr source" >&2; exit 1; }
    ctr -n "$NS" images export "$ARC" "$IMG"
    skopeo copy "oci-archive:$ARC" "oci:$LAYOUT:img" >/dev/null
    CFG=$(oci_config_file "$LAYOUT" img)
    DIFFIDS=$(jq -r '.rootfs.diff_ids[]' "$CFG")
    SIG_B64=$(jq -r --arg k "${LABEL_PREFIX}.signature" '.config.Labels[$k] // empty' "$CFG")
    CHAIN_B64=$(jq -r --arg k "${LABEL_PREFIX}.certchain" '.config.Labels[$k] // empty' "$CFG")
    ;;
esac

[[ -n $DIFFIDS   ]] || { echo "Could not read rootfs diff_ids from image" >&2; exit 1; }
[[ -n $SIG_B64   ]] || { echo "Label ${LABEL_PREFIX}.signature not found on image" >&2; exit 1; }
[[ -n $CHAIN_B64 ]] || { echo "Label ${LABEL_PREFIX}.certchain not found on image" >&2; exit 1; }

### ---- recompute LAYER_HASH and split the cert chain ----------------------

LAYER_HASH=$(printf '%s\n' "$DIFFIDS" | grep . | sha256sum | awk '{print $1}')

printf '%s' "$CHAIN_B64" | base64 -d > "$CHAIN_PEM"
# leaf = first certificate in the bundle; intermediates = the rest
awk 'BEGIN{n=0} /-----BEGIN CERTIFICATE-----/{n++} n==1{print} /-----END CERTIFICATE-----/{if(n==1) exit}' "$CHAIN_PEM" > "$LEAF_PEM"
awk 'BEGIN{n=0} /-----BEGIN CERTIFICATE-----/{n++} n>=2{print}' "$CHAIN_PEM" > "$INTER_PEM"
[[ -s $LEAF_PEM ]] || { echo "No leaf certificate in ${LABEL_PREFIX}.certchain" >&2; exit 1; }

### ---- check 1: certificate chain to the provided root CA -----------------

CHAIN_OK=0
if [[ -s $INTER_PEM ]]; then
  VERIFY_OUT=$(openssl verify -CAfile "$ROOT_CA" -untrusted "$INTER_PEM" "$LEAF_PEM" 2>&1) && CHAIN_OK=1 || true
else
  VERIFY_OUT=$(openssl verify -CAfile "$ROOT_CA" "$LEAF_PEM" 2>&1) && CHAIN_OK=1 || true
fi
if [[ $CHAIN_OK -eq 1 ]]; then
  echo "Certificate chain : VALID  (leaf chains to provided CA)"
else
  echo "Certificate chain : INVALID"
  echo "    $VERIFY_OUT" >&2
fi

### ---- check 2: signature over the recomputed LAYER_HASH ------------------

SIG_OK=0
openssl x509 -in "$LEAF_PEM" -pubkey -noout > "$PUB_PEM"
printf '%s' "$LAYER_HASH" > "$DATA"
printf '%s' "$SIG_B64" | base64 -d > "$SIG"
if openssl pkeyutl -verify -pubin -inkey "$PUB_PEM" -rawin -in "$DATA" -sigfile "$SIG" >/dev/null 2>&1; then
  SIG_OK=1
  echo "Signature         : VALID  (LAYER_HASH $LAYER_HASH signed by leaf key)"
else
  echo "Signature         : INVALID (label signature does not match image layers / leaf key)"
fi

### ---- verdict ------------------------------------------------------------

if [[ $CHAIN_OK -eq 1 && $SIG_OK -eq 1 ]]; then
  echo "RESULT            : OK"
  exit 0
fi
echo "RESULT            : FAILED"
exit 1

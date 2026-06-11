#!/usr/bin/env bash
#
# sign-image.sh
#
# Sign a container image's layer set with an X.509 key from a PKCS#12 container,
# and store the signature + cert chain (leaf + intermediate CA) as image LABELS
# WITHOUT changing the layer set.
#
# Source store is auto-detected in this priority order:
#     1. docker   (docker image inspect)
#     2. ctr       (containerd, ctr -n <ns> images ls)
#     3. buildah   (containers-storage)
# The image is exported from whichever store is found first, labelled, and the
# signed result is imported back into that same store.
#
# Labels are applied with `umoci config` on an OCI layout: it edits the image
# config blob only and adds NO filesystem layer, so rootfs diff_ids -- and thus
# LAYER_HASH -- are preserved exactly. (`buildah commit`/`docker build` would
# append an empty layer and break the signature.)
#
#   LAYER_HASH = sha256( diff_id_1 "\n" diff_id_2 "\n" ... )
# signed as its 64-char ASCII hex string, no trailing newline (original scheme).
#
set -euo pipefail

### ---- usage / arguments --------------------------------------------------

usage() {
  cat >&2 <<EOF
Usage: $0 -s SRC_IMAGE -d DEST_IMAGE -p SIGNER_P12 [-r LABEL_PREFIX] [-n CTR_NS]

  -s SRC_IMAGE     image reference to sign (as it appears in its store)
  -d DEST_IMAGE    name:tag for the signed result, written back to the SAME store
  -p SIGNER_P12    PKCS#12 file: leaf private key + leaf cert + intermediate CA
  -r LABEL_PREFIX  reverse-DNS label prefix (default: com.example.imagesign)
  -n CTR_NS        containerd namespace for ctr 
                   (default: \$CONTAINERD_NAMESPACE or "k8s.io")

PKCS#12 passphrase is read from \$P12_PASSWORD if set, otherwise prompted.
EOF
  exit 2
}

LABEL_PREFIX="org.mitel.imagesign"
NS="${CONTAINERD_NAMESPACE:-k8s.io}"
SRC_IMAGE="" DEST_IMAGE="" SIGNER_P12=""

while getopts ":s:d:p:r:n:h" opt; do
  case "$opt" in
    s) SRC_IMAGE=$OPTARG ;;
    d) DEST_IMAGE=$OPTARG ;;
    p) SIGNER_P12=$OPTARG ;;
    r) LABEL_PREFIX=$OPTARG ;;
    n) NS=$OPTARG ;;
    h) usage ;;
    *) usage ;;
  esac
done

[[ -n $SRC_IMAGE && -n $DEST_IMAGE && -n $SIGNER_P12 ]] || usage
[[ -r $SIGNER_P12 ]] || { echo "Cannot read PKCS#12 file: $SIGNER_P12" >&2; exit 1; }

# Always-required tooling (store-specific tools are checked during detection).
for bin in skopeo umoci openssl jq base64 sha256sum awk sed shred tr; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Required tool not found: $bin" >&2; exit 1; }
done

### ---- detect the source store -------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }
docker_has()  { docker image inspect "$1" >/dev/null 2>&1; }
ctr_has()     { ctr -n "$NS" images ls -q 2>/dev/null | grep -Fxq "$1"; }
buildah_has() { buildah inspect --type image "$1" >/dev/null 2>&1; }

if   have docker  && docker_has  "$SRC_IMAGE"; then SOURCE=docker
elif have ctr     && ctr_has     "$SRC_IMAGE"; then SOURCE=ctr
elif have buildah && buildah_has "$SRC_IMAGE"; then SOURCE=buildah
else
  echo "Image '$SRC_IMAGE' not found in docker, ctr (namespace '$NS'), or buildah." >&2
  echo "Check the exact reference with: docker images / ctr -n $NS images ls / buildah images" >&2
  exit 1
fi
echo "Source store: $SOURCE" >&2

### ---- passphrase ---------------------------------------------------------

if [[ -z ${P12_PASSWORD:-} ]]; then
  read -rs -p "PKCS#12 passphrase: " P12_PASSWORD; echo
fi
export P12_PASSWORD

### ---- scratch space ------------------------------------------------------
# Key material -> tmpfs (sensitive). OCI layout + archives -> disk (large).

umask 077
SECURE_BASE=/dev/shm
[[ -d $SECURE_BASE && -w $SECURE_BASE ]] || SECURE_BASE=${TMPDIR:-/tmp}
SECDIR=$(mktemp -d "$SECURE_BASE/imgsign-sec.XXXXXX")
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/imgsign-work.XXXXXX")
LAYOUT="$WORKDIR/layout"
ARC_IN="$WORKDIR/in.tar"      # export archive (docker/ctr)
ARC_OUT="$WORKDIR/out.tar"    # import archive (docker/ctr)

cleanup() {
  [[ -f $SECDIR/signer-key.pem ]] && shred -u "$SECDIR/signer-key.pem" 2>/dev/null || true
  rm -rf "$SECDIR" "$WORKDIR"
  unset P12_PASSWORD
}
trap cleanup EXIT

KEY_PEM="$SECDIR/signer-key.pem"
LEAF_PEM="$SECDIR/leaf.pem"
CA_PEM="$SECDIR/intermediate.pem"
CHAIN_PEM="$SECDIR/chain.pem"
DATA_FILE="$SECDIR/payload.bin"
OCI_TAG="img"

### ---- extract material from the PKCS#12 container ------------------------
# If the .p12 uses legacy algorithms (RC2/3DES) on OpenSSL 3.x, add `-legacy`.

openssl pkcs12 -in "$SIGNER_P12" -nocerts -nodes \
  -passin env:P12_PASSWORD -out "$KEY_PEM"
openssl pkcs12 -in "$SIGNER_P12" -clcerts -nokeys -passin env:P12_PASSWORD 2>/dev/null \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$LEAF_PEM"
openssl pkcs12 -in "$SIGNER_P12" -cacerts -nokeys -passin env:P12_PASSWORD 2>/dev/null \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$CA_PEM"

[[ -s $KEY_PEM  ]] || { echo "No private key extracted from PKCS#12 (wrong passphrase?)" >&2; exit 1; }
[[ -s $LEAF_PEM ]] || { echo "No leaf certificate extracted from PKCS#12" >&2; exit 1; }
[[ -s $CA_PEM   ]] || echo "Warning: no intermediate CA in PKCS#12; chain will be leaf-only" >&2
cat "$LEAF_PEM" "$CA_PEM" > "$CHAIN_PEM"

### ---- export source store -> OCI layout ----------------------------------

case "$SOURCE" in
  docker)
    docker save "$SRC_IMAGE" -o "$ARC_IN"
    skopeo copy "docker-archive:$ARC_IN" "oci:$LAYOUT:$OCI_TAG" >/dev/null
    ;;
  ctr)
    # containerd's exporter writes an OCI image layout archive.
    ctr -n "$NS" images export "$ARC_IN" "$SRC_IMAGE"
    skopeo copy "oci-archive:$ARC_IN" "oci:$LAYOUT:$OCI_TAG" >/dev/null
    ;;
  buildah)
    # buildah push resolves the name through buildah's own store (unlike
    # skopeo's stricter containers-storage transport).
    buildah push "$SRC_IMAGE" "oci:$LAYOUT:$OCI_TAG" >/dev/null
    ;;
esac

### ---- LAYER_HASH from the OCI layout (store-agnostic) ---------------------

oci_layout_diffids() {
  # $1 = layout dir, $2 = tag -> prints rootfs diff_ids in order
  local dir=$1 tag=$2 d mfile cfg cfgfile
  d=$(jq -r --arg t "$tag" \
        '(.manifests[] | select((.annotations["org.opencontainers.image.ref.name"]//"")==$t) | .digest) // .manifests[0].digest' \
        "$dir/index.json")
  mfile="$dir/blobs/$(printf '%s' "$d" | tr ':' '/')"
  # descend one level if this is an image index rather than a manifest
  if jq -e '.manifests' "$mfile" >/dev/null 2>&1; then
    d=$(jq -r '.manifests[0].digest' "$mfile")
    mfile="$dir/blobs/$(printf '%s' "$d" | tr ':' '/')"
  fi
  cfg=$(jq -r '.config.digest' "$mfile")
  cfgfile="$dir/blobs/$(printf '%s' "$cfg" | tr ':' '/')"
  jq -r '.rootfs.diff_ids[]' "$cfgfile"
}

layer_hash() { oci_layout_diffids "$LAYOUT" "$OCI_TAG" | grep . | sha256sum | awk '{print $1}'; }

LAYER_HASH=$(layer_hash)
[[ -n $LAYER_HASH ]] || { echo "Failed to compute LAYER_HASH" >&2; exit 1; }
echo "LAYER_HASH: $LAYER_HASH" >&2

### ---- sign LAYER_HASH ----------------------------------------------------

printf '%s' "$LAYER_HASH" > "$DATA_FILE"     # byte-identical, no trailing newline
SIG_B64=$(openssl pkeyutl -sign -inkey "$KEY_PEM" -rawin -in "$DATA_FILE" | base64 -w0)
[[ -n $SIG_B64 ]] || { echo "Signing failed" >&2; exit 1; }

# Fail fast: verify the fresh signature against the leaf cert's own public key.
openssl x509 -in "$LEAF_PEM" -pubkey -noout > "$SECDIR/leaf-pub.pem"
printf '%s' "$SIG_B64" | base64 -d > "$SECDIR/sig.bin"
if ! openssl pkeyutl -verify -pubin -inkey "$SECDIR/leaf-pub.pem" -rawin \
        -in "$DATA_FILE" -sigfile "$SECDIR/sig.bin" >/dev/null 2>&1; then
  echo "Self-verification of the fresh signature failed -- aborting" >&2
  exit 1
fi
CHAIN_B64=$(base64 -w0 < "$CHAIN_PEM")

### ---- attach labels via umoci (no new layer) -----------------------------

umoci config --image "$LAYOUT:$OCI_TAG" --no-history \
  --config.label "${LABEL_PREFIX}.signature=${SIG_B64}" \
  --config.label "${LABEL_PREFIX}.certchain=${CHAIN_B64}" \
  --config.label "${LABEL_PREFIX}.alg=ed25519"

# Guard: umoci must not have altered the layer set.
POST_HASH=$(layer_hash)
if [[ $POST_HASH != "$LAYER_HASH" ]]; then
  echo "ERROR: labelling changed the layer set ($LAYER_HASH -> $POST_HASH)." >&2
  exit 1
fi

### ---- import the signed image back into the SAME store -------------------

case "$SOURCE" in
  docker)
    skopeo copy "oci:$LAYOUT:$OCI_TAG" "docker-archive:$ARC_OUT:$DEST_IMAGE" >/dev/null
    docker load -i "$ARC_OUT" >&2
    ;;
  ctr)
    skopeo copy "oci:$LAYOUT:$OCI_TAG" "oci-archive:$ARC_OUT:$DEST_IMAGE" >/dev/null
    ctr -n "$NS" images import "$ARC_OUT" >&2
    ;;
  buildah)
    skopeo copy "oci:$LAYOUT:$OCI_TAG" "containers-storage:$DEST_IMAGE" >/dev/null
    ;;
esac

echo "Signed image '$DEST_IMAGE' written back to $SOURCE." >&2
echo "diff_ids unchanged; LAYER_HASH = $LAYER_HASH" >&2
echo "Labels: ${LABEL_PREFIX}.{signature,certchain,alg} (in .config.Labels)" >&2

// lib/images.js
// Image operations normalized across docker / crictl(+ctr).
//
// Pure parsing helpers (parseDockerImages, parseCrictlImages) are exported so
// they can be unit-tested without invoking any external command.

import { createHash, randomUUID, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import { readFile, unlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { run, CTR_NAMESPACE } from './cli.js';
import * as registry from './registry.js';

// Reverse-DNS label prefix under which the signing tooling stores its labels.
// Mirrors image-sign.sh / image-verify.sh (-r LABEL_PREFIX).
export const LABEL_PREFIX = process.env.SIGN_LABEL_PREFIX || 'org.mitel.imagesign';

// Label holding the base64 raw Ed25519 signature over LAYER_HASH.
export const SIGNATURE_LABEL = `${LABEL_PREFIX}.signature`;
// Label holding the base64 PEM bundle: leaf certificate + intermediate CAs.
export const CERTCHAIN_LABEL = `${LABEL_PREFIX}.certchain`;

// Embedded root CA used as the trust anchor when no external CA is configured.
// Keep this in sync with the EMBEDDED_CA block in image-verify.sh.
export const EMBEDDED_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIBizCCAT2gAwIBAgIEJvSEJzAFBgMrZXAwTDELMAkGA1UEBhMCREUxDjAMBgNV
BAoTBU1pdGVsMRQwEgYDVQQLEwtEZXZlbG9wbWVudDEXMBUGA1UEAxMOb2NpLXNp
Z25pbmctY2EwIBcNMjYwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMEwxCzAJ
BgNVBAYTAkRFMQ4wDAYDVQQKEwVNaXRlbDEUMBIGA1UECxMLRGV2ZWxvcG1lbnQx
FzAVBgNVBAMTDm9jaS1zaWduaW5nLWNhMCowBQYDK2VwAyEAl9seyjKY9Z08Q6uF
qGl5wWnhYiK8vqczYZgjWWOwF2mjPzA9MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFH1RavYd2ysqs/WZs+CzCr3m0/jTMAsGA1UdDwQEAwIBBjAFBgMrZXADQQC9
ms9Ru0LNfzrq/RFSXlLlHq0mic5tSPTjYjBDdEa5Euw/LY0QnR2wn3vZMI11Htr0
cjoR4gAFMUect5LoYvIC
-----END CERTIFICATE-----`;

// ---------------------------------------------------------------------------
// Signature verification helpers
// ---------------------------------------------------------------------------

/**
 * Build the canonical message bytes that are signed.
 *
 * The algorithm mirrors the shell commands used to produce the signature:
 *   1. Sort layers in their original order (already ordered by the engine).
 *   2. For each layer hash, append a newline → identical to `printf '%s\n'`.
 *   3. SHA-256 the combined string → identical to `sha256sum`.
 *   4. The *hex digest string* (64 ASCII chars) is the message passed to
 *      `openssl pkeyutl -sign -rawin`.
 *
 * @param {string[]} layers  Layer hash strings (e.g. ["sha256:abc...", ...]).
 * @returns {Buffer}         64 UTF-8 bytes of the hex digest.
 */
export function computeLayerMessage(layers) {
  const input = layers.map((l) => `${l}\n`).join('');
  const hexDigest = createHash('sha256').update(input, 'utf8').digest('hex');
  return Buffer.from(hexDigest, 'utf8');
}

/**
 * Split a PEM bundle into its individual certificate blocks (in order).
 * @param {string} pem
 * @returns {string[]}  Array of PEM-encoded certificate strings.
 */
export function splitPemCertificates(pem) {
  const matches = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches || [];
}

/**
 * Load trusted root CA certificates. Uses the file at `caPath` when it is
 * readable, otherwise falls back to the embedded root CA. Returns an array of
 * X509Certificate objects (a bundle may contain more than one root). Returns an
 * empty array only if even the embedded CA fails to parse.
 *
 * @param {string} [caPath]  Optional path to a PEM file (overrides embedded CA).
 * @returns {Promise<import('node:crypto').X509Certificate[]>}
 */
export async function loadTrustedRoots(caPath) {
  let pem = EMBEDDED_ROOT_CA_PEM;
  let source = 'embedded';
  if (caPath) {
    try {
      pem = await readFile(caPath, 'utf8');
      source = caPath;
    } catch {
      // Fall back to the embedded CA when the file cannot be read.
      pem = EMBEDDED_ROOT_CA_PEM;
      source = 'embedded';
    }
  }
  const roots = [];
  for (const block of splitPemCertificates(pem)) {
    try {
      roots.push(new X509Certificate(block));
    } catch {
      // Skip unparseable blocks.
    }
  }
  // If an external file was unusable, ensure the embedded CA is still trusted.
  if (roots.length === 0 && source !== 'embedded') {
    try {
      roots.push(new X509Certificate(EMBEDDED_ROOT_CA_PEM));
    } catch {
      /* nothing we can do */
    }
  }
  return roots;
}

/** True when `cert` is within its validity window relative to `now`. */
function isCurrentlyValid(cert, now = new Date()) {
  const from = new Date(cert.validFrom);
  const to = new Date(cert.validTo);
  return !(now < from || now > to);
}

/**
 * Verify that `leaf` chains to one of the `trustedRoots`, optionally through the
 * supplied `intermediates`. Each link is checked both by issuer/subject naming
 * (checkIssued) and cryptographically (verify against the issuer's public key),
 * and every certificate on the path must be within its validity window.
 *
 * @param {import('node:crypto').X509Certificate} leaf
 * @param {import('node:crypto').X509Certificate[]} intermediates
 * @param {import('node:crypto').X509Certificate[]} trustedRoots
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyCertChain(leaf, intermediates, trustedRoots) {
  if (!trustedRoots || trustedRoots.length === 0) {
    return { ok: false, reason: 'No trusted root CA configured' };
  }
  // Candidate issuers: supplied intermediates plus the trusted roots.
  const issuers = [...intermediates, ...trustedRoots];
  const rootSet = new Set(trustedRoots.map((c) => c.fingerprint256));

  let current = leaf;
  const seen = new Set();
  // Bound the walk to the number of available certificates to prevent loops.
  for (let depth = 0; depth <= issuers.length + 1; depth++) {
    if (!isCurrentlyValid(current)) {
      return { ok: false, reason: `Certificate "${current.subject}" is expired or not yet valid` };
    }
    if (seen.has(current.fingerprint256)) {
      return { ok: false, reason: 'Certificate chain contains a loop' };
    }
    seen.add(current.fingerprint256);

    // Find an issuer that both names and cryptographically signs `current`.
    let issuer = null;
    for (const cand of issuers) {
      if (cand.fingerprint256 === current.fingerprint256) continue;
      let issued = false;
      try {
        issued = current.checkIssued(cand) && current.verify(cand.publicKey);
      } catch {
        issued = false;
      }
      if (issued) {
        issuer = cand;
        break;
      }
    }

    if (!issuer) {
      return { ok: false, reason: 'Unable to build a chain from the leaf to a trusted root CA' };
    }
    if (rootSet.has(issuer.fingerprint256)) {
      if (!isCurrentlyValid(issuer)) {
        return { ok: false, reason: 'Trusted root CA is expired or not yet valid' };
      }
      return { ok: true };
    }
    current = issuer;
  }
  return { ok: false, reason: 'Certificate chain too long or not anchored to a trusted root CA' };
}

/**
 * Verify a single image's signature purely from its labels, mirroring
 * image-verify.sh:
 *   1. Recompute LAYER_HASH from the image's rootfs diff_ids and verify the
 *      `<prefix>.signature` label against the public key in the leaf certificate
 *      of the `<prefix>.certchain` label.
 *   2. Verify that the leaf certificate chains to a trusted root CA.
 * Both checks must pass for an overall "valid" status.
 *
 * @param {Record<string,string>|null} labels  Label map from normalizeInspect.
 * @param {string[]|null}              layers  Layer list from normalizeInspect.
 * @param {import('node:crypto').X509Certificate[]} trustedRoots  Trusted roots.
 * @returns {{
 *   status: 'unsigned'|'valid'|'invalid',
 *   reason?: string,
 *   signature?: 'valid'|'invalid',
 *   chain?: 'valid'|'invalid',
 * }}
 */
export function verifySignature(labels, layers, trustedRoots) {
  const sigB64 = labels?.[SIGNATURE_LABEL];
  const chainB64 = labels?.[CERTCHAIN_LABEL];

  // No signature label at all -> the image is simply unsigned.
  if (!sigB64) return { status: 'unsigned' };

  if (!chainB64) {
    return { status: 'invalid', reason: `Certificate chain label ${CERTCHAIN_LABEL} not found` };
  }
  if (!Array.isArray(layers) || layers.length === 0) {
    return { status: 'invalid', reason: 'No layer information available for verification' };
  }

  // Decode and parse the certificate bundle (leaf first, then intermediates).
  let certs;
  try {
    const bundlePem = Buffer.from(chainB64, 'base64').toString('utf8');
    certs = splitPemCertificates(bundlePem).map((pem) => new X509Certificate(pem));
  } catch (err) {
    return { status: 'invalid', reason: `Could not parse certificate chain: ${err.message}` };
  }
  if (certs.length === 0) {
    return { status: 'invalid', reason: 'Certificate chain label contains no certificates' };
  }
  const leaf = certs[0];
  const intermediates = certs.slice(1);

  // Check 2: certificate chain to a trusted root CA.
  const chainResult = verifyCertChain(leaf, intermediates, trustedRoots);

  // Check 1: signature over the recomputed LAYER_HASH using the leaf's key.
  let signatureOk = false;
  let signatureReason;
  try {
    const sigBuf = Buffer.from(sigB64, 'base64');
    const message = computeLayerMessage(layers);
    signatureOk = cryptoVerify(null, message, leaf.publicKey, sigBuf);
    if (!signatureOk) signatureReason = 'Signature does not match image layers / leaf key';
  } catch (err) {
    signatureReason = `Verification error: ${err.message}`;
  }

  const result = {
    signature: signatureOk ? 'valid' : 'invalid',
    chain: chainResult.ok ? 'valid' : 'invalid',
  };

  if (signatureOk && chainResult.ok) {
    return { status: 'valid', ...result };
  }
  // Surface the most relevant failure reason (signature first, then chain).
  const reason = !signatureOk ? signatureReason : chainResult.reason;
  return { status: 'invalid', reason, ...result };
}

/**
 * @typedef {Object} ImageRow
 * @property {string} id        Image ID (sha256:... or short id).
 * @property {string} repo      Repository / image name (may be '<none>').
 * @property {string} tag       Tag (may be '<none>').
 * @property {number} size      Size in bytes (0 when unknown).
 */

/** Reference string used to address an image on the CLI. */
export function imageRef(row) {
  if (row.repo && row.repo !== '<none>' && row.tag && row.tag !== '<none>') {
    return `${row.repo}:${row.tag}`;
  }
  return row.id;
}

/**
 * Parse `docker images --format '{{json .}}'` output (one JSON object per line).
 * Docker reports size as a human string (e.g. "12.3MB"); we keep the raw string
 * but also compute bytes for sorting/consistency.
 * @returns {ImageRow[]}
 */
export function parseDockerImages(stdout) {
  const rows = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let obj;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const repo = obj.Repository || '<none>';
    rows.push({
      id: obj.ID || '',
      repo: repo === '<none>' ? repo : normalizeDockerRepo(repo),
      tag: obj.Tag || '<none>',
      size: humanSizeToBytes(obj.Size),
    });
  }
  return rows;
}

/**
 * Expand a short Docker repository name to the fully-qualified form that crictl
 * displays, e.g. `mongo` -> `docker.io/library/mongo`,
 * `osem/osem` -> `docker.io/osem/osem`. Names that already carry a registry
 * host (a first path segment containing '.' or ':' or equal to 'localhost')
 * are returned unchanged.
 */
export function normalizeDockerRepo(repo) {
  const firstSegment = repo.split('/')[0];
  const hasRegistry =
    repo.includes('/') &&
    (firstSegment.includes('.') || firstSegment.includes(':') || firstSegment === 'localhost');
  if (hasRegistry) return repo;
  if (repo.includes('/')) return `docker.io/${repo}`;
  return `docker.io/library/${repo}`;
}

/**
 * Parse `crictl images -o json` output.
 * Shape: { images: [ { id, repoTags: [...], size: "12345" }, ... ] }
 * crictl reports size in bytes as a string.
 * @returns {ImageRow[]}
 */
export function parseCrictlImages(stdout) {
  let data;
  try {
    data = JSON.parse(stdout);
  } catch {
    return [];
  }
  const rows = [];
  for (const img of data.images || []) {
    const size = Number.parseInt(img.size, 10) || 0;
    const repoTags = Array.isArray(img.repoTags) ? img.repoTags : [];
    if (repoTags.length === 0) {
      rows.push({ id: img.id || '', repo: '<none>', tag: '<none>', size });
      continue;
    }
    for (const rt of repoTags) {
      const { repo, tag } = splitRepoTag(rt);
      rows.push({ id: img.id || '', repo, tag, size });
    }
  }
  return rows;
}

/** Split "repo:tag" (repo may contain a registry host with a port). */
export function splitRepoTag(repoTag) {
  const lastColon = repoTag.lastIndexOf(':');
  const lastSlash = repoTag.lastIndexOf('/');
  if (lastColon > lastSlash) {
    return { repo: repoTag.slice(0, lastColon), tag: repoTag.slice(lastColon + 1) };
  }
  return { repo: repoTag, tag: '<none>' };
}

/** Convert docker's human-readable size string to bytes (best effort). */
export function humanSizeToBytes(text) {
  if (!text) return 0;
  const m = /^([\d.]+)\s*([KMGT]?B)$/i.exec(String(text).trim());
  if (!m) return 0;
  const value = Number.parseFloat(m[1]);
  const unit = m[2].toUpperCase();
  const mult = { B: 1, KB: 1e3, MB: 1e6, GB: 1e9, TB: 1e12 }[unit] || 1;
  return Math.round(value * mult);
}

/**
 * List images for the active engine.
 * @param {import('./cli.js').Capabilities} caps
 * @returns {Promise<ImageRow[]>}
 */
export async function listImages(caps) {
  if (caps.engine === 'registry') {
    return registry.listImages(caps.registry);
  }
  if (caps.engine === 'docker') {
    const { stdout } = await run('docker', ['images', '--no-trunc', '--format', '{{json .}}']);
    return parseDockerImages(stdout);
  }
  const { stdout } = await run('crictl', ['images', '-o', 'json']);
  return parseCrictlImages(stdout);
}

/**
 * Inspect a single image, returning details. Returns the resolved id, a
 * normalized `details` object (consistent across engines), and the raw payload.
 * @returns {Promise<{id: string, details: object, raw: unknown}>}
 */
export async function inspectImage(caps, id) {
  if (caps.engine === 'registry') {
    const { id: resolvedId, configBlob } = await registry.inspectImage(caps.registry, id);
    return {
      id: resolvedId,
      details: normalizeInspect('registry', configBlob, resolvedId),
      raw: configBlob,
    };
  }
  if (caps.engine === 'docker') {
    const { stdout } = await run('docker', ['image', 'inspect', id]);
    const arr = JSON.parse(stdout);
    const obj = Array.isArray(arr) ? arr[0] : arr;
    const resolvedId = obj?.Id || id;
    return { id: resolvedId, details: normalizeInspect('docker', obj, resolvedId), raw: obj };
  }
  const { stdout } = await run('crictl', ['inspecti', '-o', 'json', id]);
  const obj = JSON.parse(stdout);
  const resolvedId = obj?.status?.id || obj?.id || id;
  return { id: resolvedId, details: normalizeInspect('crictl', obj, resolvedId), raw: obj };
}

/**
 * Normalize the engine-specific inspect payload into a stable shape consumed by
 * the UI. Missing values are returned as null so the frontend can render
 * "not found" consistently.
 *
 * @param {'docker'|'crictl'|'registry'} engine
 * @param {any} obj  Parsed inspect object for a single image. For 'registry'
 *                   this is the OCI image config blob, which mirrors crictl's
 *                   imageSpec shape (config / os / architecture / rootfs).
 * @param {string} id
 * @returns {{
 *   id: string,
 *   os: string|null,
 *   architecture: string|null,
 *   labels: Record<string,string>|null,
 *   layers: string[]|null,
 *   entrypoint: string[]|null,
 *   cmd: string[]|null,
 *   env: string[]|null,
 *   exposedPorts: string[]|null,
 * }}
 */
export function normalizeInspect(engine, obj, id) {
  // Locate the per-engine sub-objects. The registry config blob is itself the
  // spec; crictl nests it under info.imageSpec; docker uses capitalized keys.
  const spec = engine === 'docker' ? obj : engine === 'registry' ? obj : obj?.info?.imageSpec;
  const config = engine === 'docker' ? obj?.Config : spec?.config;

  const os = (engine === 'docker' ? obj?.Os : spec?.os) || null;
  const architecture = (engine === 'docker' ? obj?.Architecture : spec?.architecture) || null;

  // Layers: docker exposes RootFS.Layers; crictl exposes rootfs.diff_ids.
  const rawLayers = engine === 'docker' ? obj?.RootFS?.Layers : spec?.rootfs?.diff_ids;
  const layers = Array.isArray(rawLayers) && rawLayers.length > 0 ? rawLayers : null;

  const labels =
    config?.Labels && typeof config.Labels === 'object' && Object.keys(config.Labels).length > 0
      ? config.Labels
      : null;

  const entrypoint = nonEmptyArray(config?.Entrypoint);
  const cmd = nonEmptyArray(config?.Cmd);
  const env = nonEmptyArray(config?.Env);

  // ExposedPorts is an object keyed by "port/proto"; surface the keys.
  const exposedPorts =
    config?.ExposedPorts && typeof config.ExposedPorts === 'object'
      ? nonEmptyArray(Object.keys(config.ExposedPorts))
      : null;

  return { id, os, architecture, labels, layers, entrypoint, cmd, env, exposedPorts };
}

/** Return the array when it is a non-empty array, otherwise null. */
function nonEmptyArray(value) {
  return Array.isArray(value) && value.length > 0 ? value : null;
}

/**
 * Delete one or more images. Best-effort per image; collects per-image errors.
 * @returns {Promise<{deleted: string[], errors: {id: string, message: string}[]}>}
 */
export async function deleteImages(caps, ids) {
  const deleted = [];
  const errors = [];
  for (const id of ids) {
    try {
      if (caps.engine === 'registry') {
        await registry.deleteImage(caps.registry, id);
      } else if (caps.engine === 'docker') {
        await run('docker', ['rmi', id]);
      } else {
        await run('crictl', ['rmi', id]);
      }
      deleted.push(id);
    } catch (err) {
      errors.push({ id, message: (err.stderr || err.message || '').trim() });
    }
  }
  return { deleted, errors };
}

/**
 * Pull (download) an image by reference using the active engine.
 * @returns {Promise<{output: string}>}
 */
export async function pullImage(caps, ref) {
  // The registry backend "pulls" by copying the source ref into the configured
  // registry with skopeo; docker/crictl pull into their local store.
  if (caps.engine === 'registry') {
    const { stdout, stderr } = await run('skopeo', registry.buildPullArgs(caps.registry, ref));
    return { output: (stdout || stderr || '').trim() };
  }
  if (caps.engine === 'crictl') {
    const { stdout, stderr } = await run('crictl', ['pull', ref]);
    return { output: (stdout || stderr || '').trim() };
  }
  const { stdout, stderr } = await run('docker', ['pull', ref]);
  return { output: (stdout || stderr || '').trim() };
}

/**
 * Build the pull command for the active engine.
 * @returns {{ bin: string, args: string[] }}
 */
export function buildPullCommand(caps, ref) {
  // registry "pull" copies the source ref into the registry via skopeo.
  if (caps.engine === 'registry') return { bin: 'skopeo', args: registry.buildPullArgs(caps.registry, ref) };
  if (caps.engine === 'crictl') return { bin: 'crictl', args: ['pull', ref] };
  return { bin: 'docker', args: ['pull', ref] };
}

/**
 * Build the delete command for a single image id.
 * @returns {{ bin: string, args: string[] }}
 */
export function buildDeleteCommand(caps, id) {
  if (caps.engine === 'crictl') return { bin: 'crictl', args: ['rmi', id] };
  return { bin: 'docker', args: ['rmi', id] };
}

// ---------------------------------------------------------------------------
// Export / import via skopeo + OCI image layout
//
// All download/upload across every backend goes through skopeo into (or out of)
// a shared OCI image layout, which is then tar+xz'd. This yields one portable
// archive format so an image downloaded from any instance (registry, docker, or
// containerd) can be uploaded into any other.
//
// skopeo addresses each backend through a different transport:
//   registry   -> docker://<host>/<repo>:<tag>
//   docker     -> docker-daemon:<ref>
//   containerd -> (no skopeo transport) bridged through `ctr images export`
//                 / `ctr images import` and an intermediate OCI archive.
// ---------------------------------------------------------------------------

const noop = () => Promise.resolve();

/** Path for a short-lived intermediate archive used by the containerd bridge. */
function tmpArchivePath() {
  return path.join(os.tmpdir(), `container-ui-${randomUUID()}.tar`);
}

/**
 * Build the command steps that copy image `ref` from the active backend into the
 * OCI image layout at `layoutDir`, stored under the layout tag `layoutTag`.
 *
 * @returns {{ steps: { bin: string, args: string[] }[], cleanup: () => Promise<void> }}
 */
export function buildLayoutExportSteps(caps, ref, layoutDir, layoutTag) {
  const dest = `oci:${layoutDir}:${layoutTag}`;
  if (caps.engine === 'registry') {
    const src = `docker://${registry.dockerRef(caps.registry, ref)}`;
    return { steps: [{ bin: 'skopeo', args: registry.buildCopyArgs(caps.registry, src, dest) }], cleanup: noop };
  }
  if (caps.engine === 'docker') {
    return { steps: [{ bin: 'skopeo', args: ['copy', `docker-daemon:${ref}`, dest] }], cleanup: noop };
  }
  // containerd: export with ctr, then let skopeo read the OCI archive.
  const tmp = tmpArchivePath();
  return {
    steps: [
      { bin: 'ctr', args: ['-n', CTR_NAMESPACE, 'images', 'export', tmp, ref] },
      { bin: 'skopeo', args: ['copy', `oci-archive:${tmp}`, dest] },
    ],
    cleanup: () => unlink(tmp).catch(() => {}),
  };
}

/**
 * Build the command steps that copy one image from a skopeo-readable source
 * `src` (typically `oci:<layoutDir>:imgN`, or a `docker-archive:`/`oci-archive:`
 * reference) into the active backend under the reference `ref`.
 *
 * @returns {{ steps: { bin: string, args: string[] }[], cleanup: () => Promise<void> }}
 */
export function buildLayoutImportSteps(caps, src, ref) {
  if (caps.engine === 'registry') {
    const dest = `docker://${registry.destRefForPull(caps.registry, ref)}`;
    return { steps: [{ bin: 'skopeo', args: registry.buildCopyArgs(caps.registry, src, dest) }], cleanup: noop };
  }
  if (caps.engine === 'docker') {
    return { steps: [{ bin: 'skopeo', args: ['copy', src, `docker-daemon:${ref}`] }], cleanup: noop };
  }
  // containerd: write an OCI archive with skopeo, then import it with ctr.
  const tmp = tmpArchivePath();
  return {
    steps: [
      { bin: 'skopeo', args: ['copy', src, `oci-archive:${tmp}:${ref}`] },
      { bin: 'ctr', args: ['-n', CTR_NAMESPACE, 'images', 'import', tmp] },
    ],
    cleanup: () => unlink(tmp).catch(() => {}),
  };
}

// lib/images.js
// Image operations normalized across docker / crictl(+ctr).
//
// Pure parsing helpers (parseDockerImages, parseCrictlImages) are exported so
// they can be unit-tested without invoking any external command.

import { createHash, verify as cryptoVerify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { run, spawnStream, CTR_NAMESPACE } from './cli.js';

// OCI label used to store the Ed25519 signature (base64-encoded).
export const SIGNATURE_LABEL = 'org.opencontainers.image.signature';

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
 * Load and cache an Ed25519 public key from a PEM file.
 * Returns null when the file cannot be read or is not a valid public key.
 *
 * @param {string} keyPath  Absolute path to the PEM file.
 * @returns {Promise<import('node:crypto').KeyObject|null>}
 */
let _cachedKey = null;
let _cachedKeyPath = null;

export async function loadPublicKey(keyPath) {
  if (_cachedKeyPath === keyPath && _cachedKey !== null) return _cachedKey;
  try {
    const { createPublicKey } = await import('node:crypto');
    const pem = await readFile(keyPath, 'utf8');
    const key = createPublicKey({ key: pem, format: 'pem' });
    _cachedKey = key;
    _cachedKeyPath = keyPath;
    return key;
  } catch {
    return null;
  }
}

/** Reset the public key cache (used in tests). */
export function _resetKeyCache() {
  _cachedKey = null;
  _cachedKeyPath = null;
}

/**
 * Verify the OCI image signature for a single image.
 *
 * @param {Record<string,string>|null} labels  Label map from normalizeInspect.
 * @param {string[]|null}              layers  Layer list from normalizeInspect.
 * @param {import('node:crypto').KeyObject|null} keyObject  Loaded public key.
 * @returns {{ status: 'unsigned'|'valid'|'invalid', reason?: string }}
 */
export function verifySignature(labels, layers, keyObject) {
  const sigB64 = labels?.[SIGNATURE_LABEL];
  if (!sigB64) return { status: 'unsigned' };

  if (!keyObject) {
    return { status: 'invalid', reason: 'Public key not configured or could not be loaded' };
  }

  if (!Array.isArray(layers) || layers.length === 0) {
    return { status: 'invalid', reason: 'No layer information available for verification' };
  }

  let sigBuf;
  try {
    sigBuf = Buffer.from(sigB64, 'base64');
  } catch {
    return { status: 'invalid', reason: 'Signature label is not valid base64' };
  }

  try {
    const message = computeLayerMessage(layers);
    const ok = cryptoVerify(null, message, keyObject, sigBuf);
    return ok ? { status: 'valid' } : { status: 'invalid', reason: 'Signature does not match layer hashes' };
  } catch (err) {
    return { status: 'invalid', reason: `Verification error: ${err.message}` };
  }
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
 * @param {'docker'|'crictl'} engine
 * @param {any} obj  Parsed inspect object for a single image.
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
  // Locate the per-engine sub-objects.
  const spec = engine === 'docker' ? obj : obj?.info?.imageSpec;
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
      if (caps.engine === 'docker') {
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
  if (caps.engine === 'docker') {
    const { stdout, stderr } = await run('docker', ['pull', ref]);
    return { output: (stdout || stderr || '').trim() };
  }
  const { stdout, stderr } = await run('crictl', ['pull', ref]);
  return { output: (stdout || stderr || '').trim() };
}

/**
 * Build the pull command for the active engine.
 * @returns {{ bin: string, args: string[] }}
 */
export function buildPullCommand(caps, ref) {
  if (caps.engine === 'docker') return { bin: 'docker', args: ['pull', ref] };
  return { bin: 'crictl', args: ['pull', ref] };
}

/**
 * Build the delete command for a single image id.
 * @returns {{ bin: string, args: string[] }}
 */
export function buildDeleteCommand(caps, id) {
  if (caps.engine === 'docker') return { bin: 'docker', args: ['rmi', id] };
  return { bin: 'crictl', args: ['rmi', id] };
}

/**
 * Build the export command (engine-specific) that writes an uncompressed tar
 * stream to stdout for the given refs.
 * @returns {{ bin: string, args: string[] }}
 */
export function buildExportCommand(caps, refs) {
  if (caps.engine === 'docker') {
    return { bin: 'docker', args: ['save', ...refs] };
  }
  // ctr writes the archive to the path given; '-' means stdout.
  return { bin: 'ctr', args: ['-n', CTR_NAMESPACE, 'images', 'export', '-', ...refs] };
}

/**
 * Build the import command (engine-specific) that reads an uncompressed tar
 * stream from stdin.
 * @returns {{ bin: string, args: string[] }}
 */
export function buildImportCommand(caps) {
  if (caps.engine === 'docker') {
    return { bin: 'docker', args: ['load'] };
  }
  return { bin: 'ctr', args: ['-n', CTR_NAMESPACE, 'images', 'import', '-'] };
}

/** Spawn the export process; caller pipes its stdout onward. */
export function spawnExport(caps, refs) {
  const { bin, args } = buildExportCommand(caps, refs);
  return spawnStream(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
}

/** Spawn the import process; caller pipes a tar stream into its stdin. */
export function spawnImport(caps) {
  const { bin, args } = buildImportCommand(caps);
  return spawnStream(bin, args, { stdio: ['pipe', 'pipe', 'pipe'] });
}

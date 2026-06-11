#!/usr/bin/env node
// server.js
// Zero-dependency HTTP server (node:http) exposing the container-image web UI
// and its JSON/streaming API.

import http from 'node:http';
import { createReadStream, createWriteStream, mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { stat, unlink } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { initialize, spawnStream, run } from './lib/cli.js';
import {
  listImages,
  inspectImage,
  deleteImages,
  pullImage,
  buildPullCommand,
  buildDeleteCommand,
  buildLayoutExportSteps,
  buildLayoutImportSteps,
  loadTrustedRoots,
  verifySignature,
} from './lib/images.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = Number.parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';
// Optional override for the trust anchor. When unset (or unreadable) the
// embedded root CA in lib/images.js is used. Mirrors image-verify.sh's -c flag.
const ROOT_CA_PATH = process.env.ROOT_CA_PATH || '';

// Hosts permitted in the Host/Origin headers (DNS-rebinding & CSRF guard).
// Override with ALLOWED_HOSTS="a,b,c" when exposing the UI beyond localhost.
const ALLOWED_HOSTS = new Set(
  (process.env.ALLOWED_HOSTS || ['localhost', '127.0.0.1', '[::1]', '::1', HOST].join(','))
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean),
);

// Gated debug logging. Enable with DEBUG=1 (or LOG_LEVEL=debug). Writes to
// stderr so it never mixes into stdout payloads.
const DEBUG = /^(1|true|debug|verbose|yes)$/i.test(process.env.DEBUG || process.env.LOG_LEVEL || '');
function debug(...args) {
  if (DEBUG) console.error(`[debug ${new Date().toISOString()}]`, ...args);
}

// Maximum accepted length of a user-supplied image reference / id.
const MAX_REF_LEN = 512;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

/** Active engine capabilities, set during startup. */
let caps;

/** Trusted root CA certificates, loaded at startup. */
let trustedRoots = [];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function sendError(res, status, message) {
  sendJson(res, status, { error: message });
}

/** Read and JSON-parse a request body with a sane size cap. */
function readJsonBody(req, limit = 1 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

/**
 * Validate a single image reference or id. Rejects values that could be
 * interpreted as a command-line option (leading '-') and values containing
 * control characters / newlines. This guards against argument-injection into
 * the spawned engine CLIs and against SSE frame injection in the echoed
 * command line.
 */
export function isValidRef(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > MAX_REF_LEN) return false;
  if (s.startsWith('-')) return false;
  // Reject control characters (0x00-0x1f) and DEL (0x7f), incl. newlines.
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false;
  }
  return true;
}

/** Validate and normalize the list of ids from a JSON request body. */
function parseIds(body) {
  if (!body || !Array.isArray(body.ids)) return null;
  const ids = body.ids.filter(isValidRef);
  return ids.length > 0 ? ids : null;
}

/** Parse and validate a comma-separated id list from a query parameter. */
function parseRefList(raw) {
  const ids = (raw || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (ids.length === 0 || !ids.every(isValidRef)) return null;
  return ids;
}

// ---------------------------------------------------------------------------
// Request origin guard (DNS rebinding / CSRF)
// ---------------------------------------------------------------------------

/** Extract the hostname (sans port) from a Host header value. */
function hostnameOf(hostHeader) {
  const h = (hostHeader || '').toLowerCase().trim();
  if (!h) return '';
  if (h.startsWith('[')) return h.slice(0, h.indexOf(']') + 1); // [::1]:port
  const colon = h.indexOf(':');
  return colon === -1 ? h : h.slice(0, colon);
}

/**
 * Decide whether a request should be rejected. The Host header must name a
 * known-local host, and any Origin header (sent by browsers on cross-site and
 * all POST requests) must do the same. Returns a reason string to reject, or
 * null to allow.
 */
function rejectReason(req) {
  const host = hostnameOf(req.headers.host);
  if (host && !ALLOWED_HOSTS.has(host)) return `disallowed Host "${req.headers.host}"`;
  const origin = req.headers.origin;
  if (origin) {
    let originHost;
    try {
      originHost = new URL(origin).hostname.toLowerCase();
    } catch {
      return `invalid Origin "${origin}"`;
    }
    if (!ALLOWED_HOSTS.has(originHost)) return `cross-origin request from "${origin}"`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// SSE helpers
// ---------------------------------------------------------------------------

/** Begin an SSE response. */
function sseStart(res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
}

/** Send an SSE data line (auto line-splits multi-line text). */
function sseSend(res, text) {
  for (const line of String(text).split('\n')) {
    res.write(`data: ${line}\n`);
  }
  res.write('\n');
}

/** Send a named SSE event with JSON payload and end the stream. */
function sseDone(res, payload) {
  res.write(`event: done\ndata: ${JSON.stringify(payload)}\n\n`);
  res.end();
}

/**
 * Spawn a command and stream its combined stdout+stderr as SSE events.
 * Resolves when the process closes; sends a final `done` event with
 * { ok, code }. When endStream is false the response is kept open.
 */
function sseSpawn(res, bin, args, { endStream = true } = {}) {
  return new Promise((resolve) => {
    debug(`spawn: ${bin} ${args.join(' ')}`);
    const proc = spawnStream(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });

    proc.stdout.on('data', (d) => sseSend(res, d.toString()));
    proc.stderr.on('data', (d) => sseSend(res, d.toString()));

    proc.on('error', (err) => {
      debug(`spawn error: ${bin}: ${err.message}`);
      sseSend(res, `Error: ${err.message}`);
      if (endStream) sseDone(res, { ok: false, code: -1 });
      resolve({ ok: false, code: -1 });
    });

    proc.on('close', (code) => {
      debug(`exit: ${bin} -> ${code}`);
      if (endStream) sseDone(res, { ok: code === 0, code });
      resolve({ ok: code === 0, code });
    });

    // If the client disconnects, kill the process.
    res.on('close', () => safeKill(proc));
  });
}

/**
 * Run an async task, streaming progress lines via `emit(text)` as SSE, and
 * resolve with { ok, code }. The registry backend uses this in place of
 * `sseSpawn` for operations that are HTTP calls rather than child processes.
 * When endStream is false the response is kept open (caller sends `done`).
 */
async function sseRun(res, task, { endStream = true } = {}) {
  const emit = (text) => sseSend(res, text);
  try {
    await task(emit);
    if (endStream) sseDone(res, { ok: true, code: 0 });
    return { ok: true, code: 0 };
  } catch (err) {
    emit(`Error: ${(err && err.message) || err}`);
    if (endStream) sseDone(res, { ok: false, code: 1 });
    return { ok: false, code: 1 };
  }
}

// ---------------------------------------------------------------------------
// Static files
// ---------------------------------------------------------------------------

async function serveStatic(req, res, urlPath) {
  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
  // Resolve and ensure the result stays within PUBLIC_DIR (path-traversal guard).
  const filePath = path.resolve(PUBLIC_DIR, rel);
  if (filePath !== PUBLIC_DIR && !filePath.startsWith(PUBLIC_DIR + path.sep)) {
    sendError(res, 403, 'Forbidden');
    return;
  }
  try {
    const info = await stat(filePath);
    if (!info.isFile()) {
      sendError(res, 404, 'Not found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Content-Length': info.size,
    });
    createReadStream(filePath).pipe(res);
  } catch {
    sendError(res, 404, 'Not found');
  }
}

// ---------------------------------------------------------------------------
// API handlers
// ---------------------------------------------------------------------------

function handleCapabilities(req, res) {
  sendJson(res, 200, {
    engine: caps.engine,
    canPull: caps.canPull,
    canExport: caps.canExport,
    canImport: caps.canImport,
  });
}

async function handleList(req, res) {
  try {
    const images = await listImages(caps);
    sendJson(res, 200, { images });
  } catch (err) {
    sendError(res, 500, `Failed to list images: ${(err.stderr || err.message || '').trim()}`);
  }
}

async function handleDetails(req, res, id) {
  if (!isValidRef(id)) {
    sendError(res, 400, 'Invalid image id');
    return;
  }
  try {
    const result = await inspectImage(caps, id);
    const d = result.details;
    result.signature = verifySignature(d.labels, d.layers, trustedRoots);
    sendJson(res, 200, result);
  } catch (err) {
    sendError(res, 500, `Failed to inspect image: ${(err.stderr || err.message || '').trim()}`);
  }
}

async function handleVerify(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    sendError(res, 400, 'Invalid request body');
    return;
  }
  // Accept either { items: [{ id, ref }] } (preferred — a bare digest cannot be
  // inspected against a registry, so the caller supplies a ref) or a legacy
  // { ids: [...] } array. The response is always keyed by image id.
  const items = parseVerifyItems(body);
  if (!items) {
    sendError(res, 400, 'Expected a non-empty "items" or "ids" array');
    return;
  }
  // Inspect each image in parallel (by ref) and verify its signature.
  const entries = await Promise.all(
    items.map(async ({ id, ref }) => {
      try {
        const result = await inspectImage(caps, ref);
        const d = result.details;
        return [id, verifySignature(d.labels, d.layers, trustedRoots)];
      } catch {
        // If inspect fails we cannot determine signature state.
        return [id, { status: 'invalid', reason: 'Inspect failed' }];
      }
    }),
  );
  sendJson(res, 200, { statuses: Object.fromEntries(entries) });
}

/** Normalize a verify request body to a list of { id, ref } pairs. */
function parseVerifyItems(body) {
  if (body && Array.isArray(body.items)) {
    const items = body.items
      .filter((it) => it && isValidRef(it.id) && isValidRef(it.ref))
      .map((it) => ({ id: it.id, ref: it.ref }));
    return items.length > 0 ? items : null;
  }
  const ids = parseIds(body);
  return ids ? ids.map((id) => ({ id, ref: id })) : null;
}

async function handleDelete(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    sendError(res, 400, 'Invalid request body');
    return;
  }
  const ids = parseIds(body);
  if (!ids) {
    sendError(res, 400, 'Expected a non-empty "ids" array');
    return;
  }
  const result = await deleteImages(caps, ids);
  const status = result.errors.length > 0 ? 207 : 200;
  sendJson(res, status, result);
}

async function handlePull(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    sendError(res, 400, 'Invalid request body');
    return;
  }
  const ref = typeof body.ref === 'string' ? body.ref.trim() : '';
  if (!isValidRef(ref)) {
    sendError(res, 400, 'Expected a valid "ref"');
    return;
  }
  try {
    const result = await pullImage(caps, ref);
    sendJson(res, 200, { ok: true, ...result });
  } catch (err) {
    sendError(res, 500, `Pull failed: ${(err.stderr || err.message || '').trim()}`);
  }
}

/** SSE-streaming pull: GET /api/stream/pull?ref=... */
async function handleStreamPull(req, res, query) {
  const ref = (query.get('ref') || '').trim();
  if (!isValidRef(ref)) {
    sendError(res, 400, 'Expected a valid "ref" query parameter');
    return;
  }
  sseStart(res);
  const { bin, args } = buildPullCommand(caps, ref);
  sseSend(res, `$ ${bin} ${args.join(' ')}`);
  await sseSpawn(res, bin, args);
}

/** True if the image can still be inspected (i.e. it still exists). */
async function imageStillExists(id) {
  try {
    await inspectImage(caps, id);
    return true;
  } catch {
    return false;
  }
}

/** SSE-streaming delete: GET /api/stream/delete?ids=a,b,c */
async function handleStreamDelete(req, res, query) {
  const ids = parseRefList(query.get('ids'));
  if (!ids) {
    sendError(res, 400, 'Expected a valid "ids" query parameter');
    return;
  }
  sseStart(res);

  // Registry backend: deletion is an HTTP call, not a spawned binary.
  if (caps.engine === 'registry') {
    let ok = true;
    for (const id of ids) {
      if (res.writableEnded) return;
      sseSend(res, `Deleting ${id} from registry…`);
      const { errors } = await deleteImages(caps, [id]);
      if (errors.length > 0) {
        ok = false;
        sseSend(res, errors[0].message);
      } else {
        sseSend(res, `Deleted ${id}`);
      }
    }
    if (!res.writableEnded) sseDone(res, { ok, code: ok ? 0 : 1 });
    return;
  }

  let allOk = true;
  for (let i = 0; i < ids.length; i++) {
    if (res.writableEnded) return;
    const { bin, args } = buildDeleteCommand(caps, ids[i]);
    sseSend(res, `$ ${bin} ${args.join(' ')}`);
    const { ok } = await sseSpawn(res, bin, args, { endStream: false });
    if (!ok) {
      // The engine can report a timeout (e.g. crictl's "DeadlineExceeded")
      // even though the image was actually removed. Re-check existence and,
      // if it's gone, treat the delete as successful.
      if (await imageStillExists(ids[i])) {
        allOk = false;
      } else {
        sseSend(res, 'Image is no longer present — treating as deleted.');
      }
    }
  }
  if (!res.writableEnded) sseDone(res, { ok: allOk, code: allOk ? 0 : 1 });
}

/** SSE-streaming upload: POST /api/stream/upload?filename=... */
async function handleStreamUpload(req, res, query) {
  if (!caps.canImport) {
    sendError(res, 501, 'Image import is not supported in this environment');
    return;
  }
  const filename = (query.get('filename') || '').toLowerCase();
  const decompressor = decompressorFor(filename);
  if (decompressor === undefined) {
    sendError(res, 400, 'Unsupported file type. Use .tar, .tar.gz/.tgz, or .tar.xz');
    return;
  }

  sseStart(res);
  sseSend(res, `Importing ${query.get('filename') || 'archive'}…`);
  debug(`upload import: filename="${query.get('filename') || ''}" decompressor=${decompressor ? decompressor.bin : 'none'}`);

  // Every backend: stream the archive to disk, then load each image it contains
  // into the active store with skopeo (bridged through `ctr` for containerd).
  await streamUpload(req, res, decompressor);
}

/** Read the image references contained in a local archive via skopeo inspect. */
async function archiveTags(tmpTar, transport) {
  const { stdout } = await run('skopeo', ['inspect', `${transport}:${tmpTar}`]);
  const meta = JSON.parse(stdout);
  if (Array.isArray(meta.RepoTags) && meta.RepoTags.length > 0) return meta.RepoTags;
  return meta.Name ? [meta.Name] : [];
}

/**
 * Inspect an uploaded archive and produce the list of load jobs that copy its
 * images into the active backend, plus a cleanup function. Each job is a
 * sequence of command steps (skopeo, plus a `ctr` bridge step for containerd).
 *
 * Two archive shapes are supported:
 *   1. Our own download — a tarred OCI layout carrying a `refs.json` sidecar;
 *      each image is loaded back under the reference it came from.
 *   2. A `docker save` / OCI archive — its embedded RepoTags are used directly.
 *
 * @returns {Promise<{ jobs: { steps: {bin:string,args:string[]}[] }[], cleanup: () => void }>}
 */
async function planArchivePush(tmpTar) {
  const cleanups = [() => unlink(tmpTar).catch(() => {})];
  const cleanup = () => cleanups.forEach((c) => c());

  const addJob = (src, ref) => {
    const { steps, cleanup: stepCleanup } = buildLayoutImportSteps(caps, src, ref);
    cleanups.push(stepCleanup);
    return { steps };
  };

  let entries = '';
  try {
    entries = (await run('tar', ['-tf', tmpTar])).stdout;
  } catch {
    /* not a tar we can list; fall through to archive transports */
  }
  const isOurLayout = /(^|\/)refs\.json$/m.test(entries) && /(^|\/)oci-layout$/m.test(entries);

  if (isOurLayout) {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'container-ui-ul-'));
    cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
    await run('tar', ['-C', dir, '-xf', tmpTar]);
    const refs = JSON.parse(readFileSync(path.join(dir, 'refs.json'), 'utf8'));
    const jobs = refs.map((ref, i) => addJob(`oci:${dir}:img${i}`, ref));
    return { jobs, cleanup };
  }

  // A docker save / OCI archive: copy each tag it carries straight from the tar.
  let transport = 'docker-archive';
  let tags = [];
  try {
    tags = await archiveTags(tmpTar, 'docker-archive');
  } catch {
    try {
      transport = 'oci-archive';
      tags = await archiveTags(tmpTar, 'oci-archive');
    } catch {
      tags = [];
    }
  }
  const jobs = tags.map((tag) => addJob(`${transport}:${tmpTar}:${tag}`, tag));
  return { jobs, cleanup };
}

/** Stream an uploaded request body (decompressing as needed) to a temp file. */
function receiveArchive(req, res, decompressor, tmpTar) {
  return new Promise((resolve) => {
    const out = createWriteStream(tmpTar, { mode: 0o600 });
    let decomp = null;
    out.on('error', () => resolve(false));
    out.on('finish', () => resolve(true));
    if (decompressor) {
      decomp = spawnStream(decompressor.bin, decompressor.args, { stdio: ['pipe', 'pipe', 'pipe'] });
      if (res) decomp.stderr.on('data', (d) => sseSend(res, d.toString()));
      decomp.on('error', () => resolve(false));
      decomp.stdout.pipe(out);
      req.pipe(decomp.stdin);
    } else {
      req.pipe(out);
    }
    req.on('error', () => resolve(false));
  });
}

/**
 * Stream an uploaded archive to disk, then load each image it contains into the
 * active backend with skopeo (bridged through `ctr` for containerd). Progress is
 * sent as SSE.
 */
async function streamUpload(req, res, decompressor) {
  const tmpTar = path.join(os.tmpdir(), `container-ui-${randomUUID()}.tar`);

  const received = await receiveArchive(req, res, decompressor, tmpTar);
  if (!received) {
    sseSend(res, 'Failed to receive the uploaded archive.');
    if (!res.writableEnded) sseDone(res, { ok: false, code: 1 });
    unlink(tmpTar).catch(() => {});
    return;
  }

  const { jobs, cleanup } = await planArchivePush(tmpTar);
  if (jobs.length === 0) {
    sseSend(res, 'No tagged image found in the archive to load.');
    if (!res.writableEnded) sseDone(res, { ok: false, code: 1 });
    cleanup();
    return;
  }

  let ok = true;
  outer: for (const job of jobs) {
    for (const step of job.steps) {
      if (res.writableEnded) break outer;
      sseSend(res, `$ ${step.bin} ${step.args.join(' ')}`);
      const r = await sseSpawn(res, step.bin, step.args, { endStream: false });
      if (!r.ok) {
        ok = false;
        break; // skip remaining steps of this failed job, continue with the next
      }
    }
  }
  cleanup();
  if (!res.writableEnded) sseDone(res, { ok, code: ok ? 0 : 1 });
}

// ---------------------------------------------------------------------------
// Streaming download (two-phase: SSE-streamed export, then file fetch)
// ---------------------------------------------------------------------------

/** Prepared archives awaiting pickup: token -> { path, filename, timer }. */
const pendingDownloads = new Map();
const DOWNLOAD_TTL_MS = 10 * 60 * 1000;

/** Register a finished archive for one-time pickup; returns the token. */
function registerDownload(filePath, filename) {
  const token = randomUUID();
  const timer = setTimeout(() => {
    debug(`download expired: ${token.slice(0, 8)} (${filePath})`);
    pendingDownloads.delete(token);
    unlink(filePath).catch(() => {});
  }, DOWNLOAD_TTL_MS);
  timer.unref?.();
  pendingDownloads.set(token, { path: filePath, filename, timer });
  debug(`download registered: ${token.slice(0, 8)} -> ${filePath}`);
  return token;
}

/**
 * Download: copy each selected image into a shared OCI image layout with skopeo
 * (an OCI layout, unlike a docker-archive, holds many images), then tar + xz the
 * layout into a single archive and hand back a one-time token. Works for every
 * backend — registry and docker via a skopeo transport, containerd bridged
 * through `ctr`.
 *
 * A `refs.json` sidecar records each image's original reference (index-aligned
 * to the `img0`, `img1`, … layout tags) so the upload path can load them back
 * under the right references. Progress is streamed as SSE.
 */
async function streamDownload(res, ids, filename) {
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'container-ui-dl-'));
  const tmpXz = path.join(os.tmpdir(), `container-ui-${randomUUID()}.tar.xz`);
  const cleanupDir = () => rmSync(tmpDir, { recursive: true, force: true });
  const fail = () => {
    if (!res.writableEnded) sseDone(res, { ok: false, code: 1 });
    cleanupDir();
    unlink(tmpXz).catch(() => {});
  };

  // 1. Copy each image into the OCI layout under a simple, safe tag.
  for (let i = 0; i < ids.length; i++) {
    if (res.writableEnded) {
      cleanupDir();
      return;
    }
    const { steps, cleanup } = buildLayoutExportSteps(caps, ids[i], tmpDir, `img${i}`);
    let stepOk = true;
    for (const step of steps) {
      sseSend(res, `$ ${step.bin} ${step.args.join(' ')}`);
      const { ok } = await sseSpawn(res, step.bin, step.args, { endStream: false });
      if (!ok) {
        stepOk = false;
        break;
      }
    }
    await cleanup();
    if (!stepOk) {
      fail();
      return;
    }
  }
  writeFileSync(path.join(tmpDir, 'refs.json'), JSON.stringify(ids));

  // 2. tar the layout and compress: tar -C dir -cf - . | xz > tmpXz
  sseSend(res, `$ tar -C <layout> -cf - . | xz -z -T 0 > ${filename}`);
  const ok = await new Promise((resolve) => {
    const tar = spawnStream('tar', ['-C', tmpDir, '-cf', '-', '.'], { stdio: ['ignore', 'pipe', 'pipe'] });
    const xz = spawnStream('xz', ['-z', '-c', '-T', '0'], { stdio: ['pipe', 'pipe', 'pipe'] });
    const out = createWriteStream(tmpXz, { mode: 0o600 });
    let xzCode = null;
    let finished = false;
    let settled = false;
    const settle = (v) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    // Resolve true only once xz exited 0 *and* the file finished writing.
    const maybeOk = () => {
      if (xzCode === 0 && finished) settle(true);
    };
    tar.stderr.on('data', (d) => sseSend(res, d.toString()));
    xz.stderr.on('data', (d) => sseSend(res, d.toString()));
    tar.on('error', () => settle(false));
    xz.on('error', () => settle(false));
    out.on('error', () => settle(false));
    tar.stdout.pipe(xz.stdin);
    xz.stdout.pipe(out);
    xz.on('close', (code) => {
      xzCode = code;
      if (code !== 0) settle(false);
      else maybeOk();
    });
    out.on('finish', () => {
      finished = true;
      maybeOk();
    });
  });
  if (!ok) {
    fail();
    return;
  }

  cleanupDir();
  const token = registerDownload(tmpXz, filename);
  sseSend(res, `Archive ready: ${filename}`);
  if (!res.writableEnded) sseDone(res, { ok: true, code: 0, token, filename });
}

/**
 * SSE-streaming export: GET /api/stream/download?ids=a,b
 * Pipeline: export(stdout) -> xz(stdin->stdout) -> temp file.
 * stderr of both processes is streamed as SSE; on success the `done` event
 * carries a one-time token for fetching the archive via /api/download.
 */
async function handleStreamDownload(req, res, query) {
  if (!caps.canExport) {
    sendError(res, 501, 'Image export is not supported in this environment');
    return;
  }
  const ids = parseRefList(query.get('ids'));
  if (!ids) {
    sendError(res, 400, 'Expected a valid "ids" query parameter');
    return;
  }

  const filename = ids.length === 1 ? 'image.tar.xz' : 'images.tar.xz';

  sseStart(res);
  // Every backend: assemble an OCI layout with skopeo, then tar + xz it.
  await streamDownload(res, ids, filename);
}

/** Serve a previously prepared archive: GET /api/download?token=... */
async function handleFetchDownload(req, res, query) {
  const token = (query.get('token') || '').trim();
  const entry = pendingDownloads.get(token);
  if (!entry) {
    debug(`download fetch: token ${token.slice(0, 8) || '(empty)'} not found`);
    sendError(res, 404, 'Download not found or expired');
    return;
  }
  pendingDownloads.delete(token);
  clearTimeout(entry.timer);
  debug(`download fetch: serving ${entry.filename} (${entry.path})`);
  try {
    const info = await stat(entry.path);
    res.writeHead(200, {
      'Content-Type': 'application/x-xz',
      'Content-Disposition': `attachment; filename="${entry.filename}"`,
      'Content-Length': info.size,
    });
    createReadStream(entry.path).pipe(res);
  } catch {
    sendError(res, 404, 'Download not found or expired');
    return;
  }
  res.on('close', () => unlink(entry.path).catch(() => {}));
}

/**
 * Stream export of the given refs as a .tar.xz download.
 * Pipeline: export(stdout) -> xz(stdin->stdout) -> HTTP response.
 */
async function handleDownload(req, res) {
  if (!caps.canExport) {
    sendError(res, 501, 'Image export is not supported in this environment');
    return;
  }
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    sendError(res, 400, 'Invalid request body');
    return;
  }
  const ids = parseIds(body);
  if (!ids) {
    sendError(res, 400, 'Expected a non-empty "ids" array');
    return;
  }

  const filename = ids.length === 1 ? 'image.tar.xz' : 'images.tar.xz';

  // Every backend: copy each image into a shared OCI layout with skopeo (bridged
  // through `ctr` for containerd), then stream it (tar | xz) to the client. An
  // OCI layout holds many images; a docker-archive cannot. A refs.json sidecar
  // records the original refs so upload can restore them.
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'container-ui-dl-'));
  const dropDir = () => rmSync(tmpDir, { recursive: true, force: true });
  try {
    for (let i = 0; i < ids.length; i++) {
      const { steps, cleanup } = buildLayoutExportSteps(caps, ids[i], tmpDir, `img${i}`);
      try {
        for (const step of steps) await run(step.bin, step.args);
      } finally {
        await cleanup();
      }
    }
    writeFileSync(path.join(tmpDir, 'refs.json'), JSON.stringify(ids));
  } catch (err) {
    dropDir();
    sendError(res, 500, `Export failed: ${(err.stderr || err.message || '').trim()}`);
    return;
  }

  res.writeHead(200, {
    'Content-Type': 'application/x-xz',
    'Content-Disposition': `attachment; filename="${filename}"`,
  });
  const tar = spawnStream('tar', ['-C', tmpDir, '-cf', '-', '.'], { stdio: ['ignore', 'pipe', 'pipe'] });
  const xz = spawnStream('xz', ['-z', '-c', '-T', '0'], { stdio: ['pipe', 'pipe', 'pipe'] });
  tar.stdout.pipe(xz.stdin);
  xz.stdout.pipe(res);
  xz.on('close', dropDir);
  tar.on('error', () => res.destroy());
  xz.on('error', () => {
    dropDir();
    res.destroy();
  });
  res.on('close', () => {
    safeKill(tar);
    safeKill(xz);
  });
}

/**
 * Import an uploaded archive. The raw request body is the archive; its original
 * filename (for format detection) is provided via the `filename` query param.
 * Pipeline: request body -> [decompressor] -> import(stdin).
 */
async function handleUpload(req, res, query) {
  if (!caps.canImport) {
    sendError(res, 501, 'Image import is not supported in this environment');
    return;
  }
  const filename = (query.get('filename') || '').toLowerCase();
  const decompressor = decompressorFor(filename);
  if (decompressor === undefined) {
    sendError(res, 400, 'Unsupported file type. Use .tar, .tar.gz/.tgz, or .tar.xz');
    return;
  }

  // Every backend: receive to a temp file, then load each image with skopeo
  // (bridged through `ctr` for containerd).
  const tmpTar = path.join(os.tmpdir(), `container-ui-${randomUUID()}.tar`);
  const received = await receiveArchive(req, null, decompressor, tmpTar);
  if (!received) {
    unlink(tmpTar).catch(() => {});
    sendError(res, 500, 'Failed to receive the uploaded archive');
    return;
  }
  const { jobs, cleanup } = await planArchivePush(tmpTar);
  if (jobs.length === 0) {
    cleanup();
    sendError(res, 500, 'No tagged image found in the archive to load');
    return;
  }
  const loaded = [];
  try {
    for (const job of jobs) {
      for (const step of job.steps) {
        const { stdout, stderr } = await run(step.bin, step.args);
        const line = (stdout || stderr || '').trim();
        if (line) loaded.push(line);
      }
    }
  } catch (err) {
    cleanup();
    sendError(res, 500, `Load failed: ${(err.stderr || err.message || '').trim()}`);
    return;
  }
  cleanup();
  sendJson(res, 200, { ok: true, output: loaded.join('\n').trim() });
}

/**
 * Choose a decompressor for an uploaded filename.
 * Returns null for plain tar (no decompression), a {bin,args} spec for
 * compressed formats, or undefined for unsupported extensions.
 */
export function decompressorFor(filename) {
  if (filename.endsWith('.tar')) return null;
  if (filename.endsWith('.tar.gz') || filename.endsWith('.tgz')) {
    return { bin: 'gzip', args: ['-d', '-c'] };
  }
  if (filename.endsWith('.tar.xz')) {
    return { bin: 'xz', args: ['-d', '-c'] };
  }
  return undefined;
}

function safeKill(proc) {
  if (proc && !proc.killed) {
    try {
      proc.kill('SIGKILL');
    } catch {
      /* ignore */
    }
  }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

async function router(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const { pathname } = url;
  const { method } = req;

  // Log the request (path only — query strings may carry a download token).
  debug(`${method} ${pathname} from ${req.socket.remoteAddress}`);

  // DNS-rebinding / CSRF guard: reject requests with a foreign Host or Origin.
  const reason = rejectReason(req);
  if (reason) {
    console.warn(`[security] blocked ${method} ${pathname}: ${reason}`);
    sendError(res, 403, 'Forbidden');
    return;
  }

  if (pathname.startsWith('/api/')) {
    try {
      if (method === 'GET' && pathname === '/api/capabilities') return handleCapabilities(req, res);
      if (method === 'GET' && pathname === '/api/images') return await handleList(req, res);
      if (method === 'POST' && pathname === '/api/images/delete') return await handleDelete(req, res);
      if (method === 'POST' && pathname === '/api/images/pull') return await handlePull(req, res);
      if (method === 'POST' && pathname === '/api/images/verify') return await handleVerify(req, res);
      if (method === 'POST' && pathname === '/api/images/download') return await handleDownload(req, res);
      if (method === 'POST' && pathname === '/api/images/upload') return await handleUpload(req, res, url.searchParams);
      if (method === 'POST' && pathname === '/api/stream/upload') return await handleStreamUpload(req, res, url.searchParams);
      if (method === 'GET' && pathname === '/api/stream/pull') return await handleStreamPull(req, res, url.searchParams);
      if (method === 'GET' && pathname === '/api/stream/delete') return await handleStreamDelete(req, res, url.searchParams);
      if (method === 'GET' && pathname === '/api/stream/download') return await handleStreamDownload(req, res, url.searchParams);
      if (method === 'GET' && pathname === '/api/download') return await handleFetchDownload(req, res, url.searchParams);

      const detailsMatch = /^\/api\/images\/([^/]+)$/.exec(pathname);
      if (method === 'GET' && detailsMatch) {
        return await handleDetails(req, res, decodeURIComponent(detailsMatch[1]));
      }

      sendError(res, 404, 'Unknown API endpoint');
    } catch (err) {
      if (!res.headersSent) sendError(res, 500, (err.message || 'Internal error').trim());
    }
    return;
  }

  if (method === 'GET') {
    await serveStatic(req, res, pathname);
    return;
  }

  sendError(res, 405, 'Method not allowed');
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function main() {
  caps = await initialize();

  trustedRoots = await loadTrustedRoots(ROOT_CA_PATH);
  if (trustedRoots.length === 0) {
    console.warn(
      'Warning: no trusted root CA could be loaded.\n' +
        '         Signed images will show as invalid. Set ROOT_CA_PATH to override.',
    );
  } else if (ROOT_CA_PATH) {
    console.log(`Trusted root CA loaded from ${ROOT_CA_PATH} (${trustedRoots.length} cert(s))`);
  } else {
    console.log(`Using embedded trusted root CA (${trustedRoots.length} cert(s))`);
  }

  const server = http.createServer((req, res) => {
    router(req, res).catch((err) => {
      if (!res.headersSent) sendError(res, 500, (err.message || 'Internal error').trim());
    });
  });

  server.listen(PORT, HOST, () => {
    console.log(`container-ui listening on http://${HOST}:${PORT}`);
    console.log(`Allowed hosts: ${[...ALLOWED_HOSTS].join(', ')} (override with ALLOWED_HOSTS)`);
    if (DEBUG) console.log('Debug logging enabled (DEBUG=1).');
  });
}

// Only run when executed directly (not when imported by tests).
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

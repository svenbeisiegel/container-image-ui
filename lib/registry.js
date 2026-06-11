// lib/registry.js
// Remote container-registry backend.
//
// Image operations (list-tags, inspect, copy/pull, delete, push) are performed
// with the `skopeo` CLI over the docker:// transport — skopeo is a HARD
// REQUIREMENT for this backend. skopeo handles auth, TLS, and blob transfer
// uniformly, which keeps this module small and removes any need for a local
// container engine (docker/ctr).
//
// The one thing skopeo cannot do is enumerate repositories, so the catalog is
// fetched directly from the registry's HTTP API (/v2/_catalog). That small HTTP
// client (with Basic auth + custom CA / insecure support) lives here too and is
// used only for the catalog and the reachability probe.
//
// Credentials are never passed on the skopeo command line (which would leak via
// `ps` and the echoed progress lines). Instead `setupSkopeoEnv()` writes a
// 0600 auth file and points REGISTRY_AUTH_FILE at it; child skopeo processes
// inherit it from the environment.

import http from 'node:http';
import https from 'node:https';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { run } from './cli.js';

const DEFAULT_TIMEOUT_MS = 15000;
const MAX_REDIRECTS = 5;
// Bounded concurrency for the per-repo / per-tag skopeo inspect calls.
const LIST_CONCURRENCY = 6;

/**
 * @typedef {Object} RegistryConfig
 * @property {string}  base      Registry base URL, no trailing slash.
 * @property {string}  host      URL host[:port], used to build docker refs.
 * @property {string=} username  Registry username.
 * @property {string=} password  Registry password.
 * @property {string=} caPath    Optional PEM CA bundle for the registry TLS cert.
 * @property {boolean} insecure  Skip TLS verification when true.
 */

/**
 * Build the registry configuration from environment variables, or return null
 * when REGISTRY_URL is unset or not a valid http(s) URL.
 * @returns {RegistryConfig|null}
 */
export function registryConfigFromEnv(env = process.env) {
  const raw = (env.REGISTRY_URL || '').trim();
  if (!raw) return null;
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  return {
    base: raw.replace(/\/+$/, ''),
    host: url.host,
    username: env.REGISTRY_USERNAME || undefined,
    password: env.REGISTRY_PASSWORD || undefined,
    caPath: env.REGISTRY_CA_PATH || undefined,
    insecure: /^(1|true|yes)$/i.test(env.REGISTRY_INSECURE || ''),
  };
}

// ---------------------------------------------------------------------------
// HTTP client — used only for the catalog and the reachability probe.
// ---------------------------------------------------------------------------

/** Cache of CA file contents so we don't re-read on every request. */
const caCache = new Map();
function loadCa(caPath) {
  if (!caPath) return undefined;
  if (caCache.has(caPath)) return caCache.get(caPath);
  let ca;
  try {
    ca = readFileSync(caPath);
  } catch {
    ca = undefined;
  }
  caCache.set(caPath, ca);
  return ca;
}

/** Authorization header value for Basic auth, or undefined when no creds. */
function basicAuth(config) {
  if (!config.username && !config.password) return undefined;
  const token = Buffer.from(`${config.username || ''}:${config.password || ''}`).toString('base64');
  return `Basic ${token}`;
}

/**
 * Perform a single HTTP(S) request against the registry, following redirects.
 * @returns {Promise<{ status: number, headers: import('node:http').IncomingHttpHeaders, body: Buffer }>}
 */
export function request(config, method, pathOrUrl, opts = {}) {
  return doRequest(config, method, pathOrUrl, opts, 0);
}

function doRequest(config, method, pathOrUrl, opts, redirectCount) {
  return new Promise((resolve, reject) => {
    const url = pathOrUrl.startsWith('http') ? new URL(pathOrUrl) : new URL(config.base + pathOrUrl);
    const isHttps = url.protocol === 'https:';
    const transport = isHttps ? https : http;

    const headers = { ...(opts.headers || {}) };
    if (url.host === config.host) {
      const auth = basicAuth(config);
      if (auth) headers.Authorization = auth;
    }

    const reqOpts = {
      method,
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      headers,
    };
    if (isHttps) {
      if (config.insecure) reqOpts.rejectUnauthorized = false;
      const ca = loadCa(config.caPath);
      if (ca) reqOpts.ca = ca;
    }

    const req = transport.request(reqOpts, (res) => {
      const status = res.statusCode || 0;
      const location = res.headers.location;
      if (location && status >= 300 && status < 400) {
        res.resume();
        if (redirectCount >= MAX_REDIRECTS) {
          reject(new Error(`Too many redirects from ${pathOrUrl}`));
          return;
        }
        const next = new URL(location, url).toString();
        doRequest(config, method, next, opts, redirectCount + 1).then(resolve, reject);
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status, headers: res.headers, body: Buffer.concat(chunks) }));
    });

    req.on('error', reject);
    req.setTimeout(DEFAULT_TIMEOUT_MS, () => {
      req.destroy(new Error(`Request to ${url.host} timed out`));
    });
    req.end();
  });
}

/**
 * Reachability probe. Resolves true when an (authenticated) GET /v2/ returns
 * 200, false on any connection error, timeout, or auth/other status.
 * @returns {Promise<boolean>}
 */
export async function probe(config) {
  try {
    const res = await request(config, 'GET', '/v2/');
    return res.status === 200;
  } catch {
    return false;
  }
}

/** Extract the URL from a Link: <url>; rel="next" header, or null. */
function nextPageUrl(linkHeader) {
  if (!linkHeader) return null;
  const m = /<([^>]+)>;\s*rel="next"/.exec(linkHeader);
  return m ? m[1] : null;
}

/** Parse a JSON registry response body, returning a fallback on failure. */
function parseJson(res, fallback) {
  try {
    return JSON.parse(res.body.toString('utf8'));
  } catch {
    return fallback;
  }
}

/** Fetch all items from a paginated /v2/ list endpoint, following Link headers. */
async function fetchAllPages(config, initialPath, key) {
  const items = [];
  let nextPath = initialPath;
  while (nextPath) {
    const res = await request(config, 'GET', nextPath);
    if (res.status < 200 || res.status >= 300) break;
    const data = parseJson(res, {});
    for (const item of data[key] || []) items.push(item);
    const next = nextPageUrl(res.headers.link);
    if (!next) break;
    nextPath = next;
  }
  return items;
}

/** List all repository names in the registry (no skopeo equivalent exists). */
export async function listRepositories(config) {
  return fetchAllPages(config, '/v2/_catalog?n=100', 'repositories');
}

// ---------------------------------------------------------------------------
// Reference helpers
// ---------------------------------------------------------------------------

/**
 * Split an image reference into the registry repository path and a reference
 * (tag or digest). A leading "<host>/" is stripped.
 * @returns {{ repoPath: string, reference: string }}
 */
export function parseRef(config, ref) {
  let s = String(ref);
  if (config.host && s.startsWith(`${config.host}/`)) s = s.slice(config.host.length + 1);
  const at = s.indexOf('@');
  if (at !== -1) return { repoPath: s.slice(0, at), reference: s.slice(at + 1) };
  const lastColon = s.lastIndexOf(':');
  const lastSlash = s.lastIndexOf('/');
  if (lastColon > lastSlash) return { repoPath: s.slice(0, lastColon), reference: s.slice(lastColon + 1) };
  return { repoPath: s, reference: 'latest' };
}

/** Strip a leading registry host (first segment containing '.'/':' or 'localhost'). */
function stripRegistryHost(ref) {
  const slash = ref.indexOf('/');
  if (slash !== -1) {
    const first = ref.slice(0, slash);
    if (first.includes('.') || first.includes(':') || first === 'localhost') return ref.slice(slash + 1);
  }
  return ref;
}

/** Ensure a reference is prefixed with the registry host (idempotent). */
export function dockerRef(config, ref) {
  const s = String(ref);
  return s.startsWith(`${config.host}/`) ? s : `${config.host}/${s}`;
}

/**
 * Destination reference for a pull (copy into the configured registry): the
 * source repository path (its own registry host removed) under our host.
 * e.g. "docker.io/library/nginx:latest" -> "<host>/library/nginx:latest".
 */
export function destRefForPull(config, sourceRef) {
  return `${config.host}/${stripRegistryHost(String(sourceRef))}`;
}

// ---------------------------------------------------------------------------
// skopeo auth / TLS plumbing
// ---------------------------------------------------------------------------

let authFilePath = null;
let certDirPath = null;

/**
 * Prepare skopeo's environment: write a private auth file with the registry
 * credentials and (if a custom CA is configured) a cert directory, then export
 * REGISTRY_AUTH_FILE so every child skopeo process inherits the credentials
 * without exposing them on the command line. Call once at startup.
 */
export function setupSkopeoEnv(config) {
  if (config.username || config.password) {
    const token = Buffer.from(`${config.username || ''}:${config.password || ''}`).toString('base64');
    const auth = { auths: { [config.host]: { auth: token } } };
    const dir = mkdtempSync(path.join(tmpdir(), 'container-ui-auth-'));
    authFilePath = path.join(dir, 'auth.json');
    writeFileSync(authFilePath, JSON.stringify(auth), { mode: 0o600 });
    process.env.REGISTRY_AUTH_FILE = authFilePath;
  }
  if (config.caPath) {
    try {
      const ca = readFileSync(config.caPath);
      const dir = mkdtempSync(path.join(tmpdir(), 'container-ui-certs-'));
      writeFileSync(path.join(dir, 'ca.crt'), ca, { mode: 0o600 });
      certDirPath = dir;
    } catch {
      certDirPath = null;
    }
  }
}

/** TLS flags for a single-endpoint skopeo command (inspect/delete/list-tags). */
function tlsArgsSingle(config) {
  const args = [];
  if (config.insecure) args.push('--tls-verify=false');
  if (certDirPath) args.push('--cert-dir', certDirPath);
  return args;
}

/** True when a skopeo endpoint addresses our registry over docker://. */
function isOurDockerEndpoint(config, endpoint) {
  if (!endpoint.startsWith('docker://')) return false;
  const rest = endpoint.slice('docker://'.length);
  return rest === config.host || rest.startsWith(`${config.host}/`);
}

/**
 * Build a `skopeo copy` argument list, applying TLS flags only to whichever
 * endpoint(s) address our registry (an external source keeps default security).
 * @returns {string[]}  Args after the 'skopeo' binary (starts with 'copy').
 */
export function buildCopyArgs(config, srcEndpoint, destEndpoint) {
  const args = ['copy'];
  const srcOurs = isOurDockerEndpoint(config, srcEndpoint);
  const destOurs = isOurDockerEndpoint(config, destEndpoint);
  if (config.insecure) {
    if (srcOurs) args.push('--src-tls-verify=false');
    if (destOurs) args.push('--dest-tls-verify=false');
  }
  if (certDirPath) {
    if (srcOurs) args.push('--src-cert-dir', certDirPath);
    if (destOurs) args.push('--dest-cert-dir', certDirPath);
  }
  args.push(srcEndpoint, destEndpoint);
  return args;
}

/** Build the `skopeo copy` args to pull a source ref into the registry. */
export function buildPullArgs(config, sourceRef) {
  return buildCopyArgs(
    config,
    `docker://${sourceRef}`,
    `docker://${destRefForPull(config, sourceRef)}`,
  );
}

// ---------------------------------------------------------------------------
// skopeo operations
// ---------------------------------------------------------------------------

/** Run a skopeo subcommand and parse its JSON stdout. */
async function skopeoJson(args) {
  const { stdout } = await run('skopeo', args);
  return JSON.parse(stdout);
}

/** Total compressed image size from a `skopeo inspect` result's LayersData. */
export function inspectSize(meta) {
  if (!Array.isArray(meta?.LayersData)) return 0;
  return meta.LayersData.reduce((sum, l) => sum + (Number(l.Size) || 0), 0);
}

/**
 * List all images as ImageRow[]. Repositories come from the HTTP catalog; tags
 * from `skopeo list-tags`; the digest + size from `skopeo inspect`. The repo
 * name carries the host so the resulting ref is directly usable with skopeo.
 * @returns {Promise<import('./images.js').ImageRow[]>}
 */
export async function listImages(config) {
  const repositories = await listRepositories(config);

  const pairs = [];
  await mapLimit(repositories, LIST_CONCURRENCY, async (repo) => {
    try {
      const out = await skopeoJson(['list-tags', ...tlsArgsSingle(config), `docker://${config.host}/${repo}`]);
      for (const tag of out.Tags || []) pairs.push({ repo, tag });
    } catch {
      // Skip repositories we cannot enumerate.
    }
  });

  return mapLimit(pairs, LIST_CONCURRENCY, async ({ repo, tag }) => {
    const row = { id: '', repo: `${config.host}/${repo}`, tag, size: 0 };
    try {
      const meta = await skopeoJson(['inspect', ...tlsArgsSingle(config), `docker://${config.host}/${repo}:${tag}`]);
      row.id = meta.Digest || '';
      row.size = inspectSize(meta);
    } catch {
      // Surface the tag even when its manifest could not be read.
    }
    return row;
  });
}

/**
 * Inspect an image. Returns the manifest digest (id) and the OCI image config
 * blob (which carries rootfs.diff_ids + config.Labels for signature checks).
 * The two skopeo calls run in parallel so latency matches a single call.
 * @returns {Promise<{ id: string, configBlob: any }>}
 */
export async function inspectImage(config, ref) {
  const dref = `docker://${dockerRef(config, ref)}`;
  const tls = tlsArgsSingle(config);
  const [meta, configBlob] = await Promise.all([
    skopeoJson(['inspect', ...tls, dref]),
    skopeoJson(['inspect', '--config', ...tls, dref]),
  ]);
  return { id: meta.Digest || ref, configBlob };
}

/** Delete an image (by tag or digest) from the registry. */
export async function deleteImage(config, ref) {
  await run('skopeo', ['delete', ...tlsArgsSingle(config), `docker://${dockerRef(config, ref)}`]);
}

/** Run `mapper` over `items` with bounded concurrency, preserving order. */
async function mapLimit(items, limit, mapper) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await mapper(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

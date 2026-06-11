// lib/cli.js
// Host-prerequisite checks and container-engine detection.
//
// Responsibilities:
//   1. Verify required host binaries (tar, xz, gzip) are present.
//   2. Detect the active container engine: docker first, then crictl.
//   3. When the engine is crictl, probe for `ctr` to decide whether image
//      export/import (download/upload) can be supported.
//
// The module exposes a `capabilities` object describing what the running
// environment can do, plus thin spawn/execFile wrappers used by lib/images.js.

import { execFile, spawn } from 'node:child_process';

/**
 * @typedef {Object} Capabilities
 * @property {'docker'|'crictl'} engine   Active container engine.
 * @property {boolean} canExport          Whether download (export) is supported.
 * @property {boolean} canImport          Whether upload (import) is supported.
 * @property {string}  exporter           Binary used for export ('docker' | 'ctr').
 * @property {string}  importer           Binary used for import ('docker' | 'ctr').
 */

const REQUIRED_HOST_BINARIES = ['tar', 'xz', 'gzip'];

// Namespace that Kubernetes images live under inside containerd.
export const CTR_NAMESPACE = 'k8s.io';

/**
 * Run a binary with args and resolve with { stdout, stderr }.
 * Rejects on non-zero exit or spawn failure.
 */
export function run(bin, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(bin, args, { maxBuffer: 64 * 1024 * 1024, ...opts }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout;
        err.stderr = stderr;
        reject(err);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

/**
 * Spawn a binary for streaming use (stdin/stdout piping).
 * Returns the ChildProcess.
 */
export function spawnStream(bin, args, opts = {}) {
  return spawn(bin, args, opts);
}

/**
 * Returns true when `bin` is present and executable on PATH.
 * Uses `--version` which is universally cheap and side-effect free.
 */
async function hasBinary(bin) {
  try {
    await run(bin, ['--version']);
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify all required host binaries exist. Returns the list of missing ones.
 */
export async function findMissingHostBinaries() {
  const checks = await Promise.all(
    REQUIRED_HOST_BINARIES.map(async (bin) => ({ bin, present: await hasBinary(bin) })),
  );
  return checks.filter((c) => !c.present).map((c) => c.bin);
}

/**
 * Detect engine + capabilities. Returns a Capabilities object, or null when no
 * supported engine is available.
 * @returns {Promise<Capabilities|null>}
 */
export async function detectCapabilities() {
  if (await hasBinary('docker')) {
    return {
      engine: 'docker',
      canExport: true,
      canImport: true,
      exporter: 'docker',
      importer: 'docker',
    };
  }

  if (await hasBinary('crictl')) {
    const hasCtr = await hasBinary('ctr');
    return {
      engine: 'crictl',
      canExport: hasCtr,
      canImport: hasCtr,
      exporter: hasCtr ? 'ctr' : '',
      importer: hasCtr ? 'ctr' : '',
    };
  }

  return null;
}

/**
 * Full startup gate: validates host prerequisites and engine availability.
 * On any unrecoverable problem it prints a helpful message and exits the
 * process. On success it returns the Capabilities object.
 * @returns {Promise<Capabilities>}
 */
export async function initialize() {
  const missing = await findMissingHostBinaries();
  if (missing.length > 0) {
    console.error(
      `\nMissing required host command(s): ${missing.join(', ')}.\n` +
        `Please install them and ensure they are on PATH before starting container-ui.\n`,
    );
    process.exit(1);
  }

  const caps = await detectCapabilities();
  if (!caps) {
    console.error(
      `\nNo supported container engine found.\n` +
        `container-ui requires either 'docker' or 'crictl' to be installed and on PATH.\n`,
    );
    process.exit(1);
  }

  console.log(`Container engine: ${caps.engine}`);
  if (caps.engine === 'crictl' && !caps.canExport) {
    console.warn(
      `Note: 'ctr' was not found. Image download/upload will be disabled. ` +
        `Install containerd's 'ctr' to enable export/import.`,
    );
  }

  return caps;
}

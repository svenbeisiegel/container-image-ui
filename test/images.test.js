// test/images.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign, createHash } from 'node:crypto';

import {
  parseDockerImages,
  parseCrictlImages,
  splitRepoTag,
  humanSizeToBytes,
  imageRef,
  normalizeDockerRepo,
  normalizeInspect,
  buildExportCommand,
  buildImportCommand,
  computeLayerMessage,
  verifySignature,
  SIGNATURE_LABEL,
  _resetKeyCache,
} from '../lib/images.js';

test('parseDockerImages parses JSON lines and converts size', () => {
  const stdout =
    '{"ID":"sha256:aaa","Repository":"nginx","Tag":"1.25","Size":"187MB"}\n' +
    '{"ID":"sha256:bbb","Repository":"<none>","Tag":"<none>","Size":"5.2MB"}\n' +
    '\n';
  const rows = parseDockerImages(stdout);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0], { id: 'sha256:aaa', repo: 'docker.io/library/nginx', tag: '1.25', size: 187_000_000 });
  assert.equal(rows[1].repo, '<none>');
  assert.equal(rows[1].size, 5_200_000);
});

test('normalizeDockerRepo expands names to crictl-style fully-qualified form', () => {
  assert.equal(normalizeDockerRepo('mongo'), 'docker.io/library/mongo');
  assert.equal(normalizeDockerRepo('osem/osem'), 'docker.io/osem/osem');
  assert.equal(normalizeDockerRepo('registry.io/team/app'), 'registry.io/team/app');
  assert.equal(normalizeDockerRepo('localhost:5000/app'), 'localhost:5000/app');
  assert.equal(normalizeDockerRepo('ghcr.io/owner/repo'), 'ghcr.io/owner/repo');
});

test('parseDockerImages ignores malformed lines', () => {
  const rows = parseDockerImages('not json\n{"ID":"x","Repository":"r","Tag":"t","Size":"1KB"}');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].size, 1000);
  assert.equal(rows[0].repo, 'docker.io/library/r');
});

test('parseCrictlImages expands repoTags and parses byte sizes', () => {
  const stdout = JSON.stringify({
    images: [
      { id: 'sha256:1', repoTags: ['registry.io:5000/app:v1'], size: '12345' },
      { id: 'sha256:2', repoTags: [], size: '99' },
      { id: 'sha256:3', repoTags: ['a:1', 'a:2'], size: '10' },
    ],
  });
  const rows = parseCrictlImages(stdout);
  assert.equal(rows.length, 4);
  assert.deepEqual(rows[0], { id: 'sha256:1', repo: 'registry.io:5000/app', tag: 'v1', size: 12345 });
  assert.deepEqual(rows[1], { id: 'sha256:2', repo: '<none>', tag: '<none>', size: 99 });
  assert.equal(rows[2].tag, '1');
  assert.equal(rows[3].tag, '2');
});

test('parseCrictlImages tolerates invalid JSON', () => {
  assert.deepEqual(parseCrictlImages('garbage'), []);
});

test('splitRepoTag handles registry ports', () => {
  assert.deepEqual(splitRepoTag('registry.io:5000/app:v1'), { repo: 'registry.io:5000/app', tag: 'v1' });
  assert.deepEqual(splitRepoTag('nginx:latest'), { repo: 'nginx', tag: 'latest' });
  assert.deepEqual(splitRepoTag('localhost:5000/x'), { repo: 'localhost:5000/x', tag: '<none>' });
});

test('humanSizeToBytes converts units', () => {
  assert.equal(humanSizeToBytes('1KB'), 1000);
  assert.equal(humanSizeToBytes('1.5 MB'), 1_500_000);
  assert.equal(humanSizeToBytes('2GB'), 2_000_000_000);
  assert.equal(humanSizeToBytes(''), 0);
  assert.equal(humanSizeToBytes('weird'), 0);
});

test('imageRef prefers repo:tag, falls back to id', () => {
  assert.equal(imageRef({ id: 'sha256:1', repo: 'nginx', tag: '1.25' }), 'nginx:1.25');
  assert.equal(imageRef({ id: 'sha256:1', repo: '<none>', tag: '<none>' }), 'sha256:1');
});

test('buildExportCommand picks engine-specific command', () => {
  assert.deepEqual(buildExportCommand({ engine: 'docker' }, ['a', 'b']), {
    bin: 'docker',
    args: ['save', 'a', 'b'],
  });
  assert.deepEqual(buildExportCommand({ engine: 'crictl' }, ['a']), {
    bin: 'ctr',
    args: ['-n', 'k8s.io', 'images', 'export', '-', 'a'],
  });
});

test('buildImportCommand picks engine-specific command', () => {
  assert.deepEqual(buildImportCommand({ engine: 'docker' }), { bin: 'docker', args: ['load'] });
  assert.deepEqual(buildImportCommand({ engine: 'crictl' }), {
    bin: 'ctr',
    args: ['-n', 'k8s.io', 'images', 'import', '-'],
  });
});

test('normalizeInspect extracts docker fields', () => {
  const obj = {
    Id: 'sha256:abc',
    Os: 'linux',
    Architecture: 'amd64',
    Config: {
      Cmd: ['/bin/bash'],
      Entrypoint: null,
      Env: ['PATH=/usr/bin', 'NODE_ENV=production'],
      ExposedPorts: { '80/tcp': {}, '443/tcp': {} },
      Labels: { 'org.opencontainers.image.vendor': 'openSUSE Project' },
    },
    RootFS: { Type: 'layers', Layers: ['sha256:layer1'] },
  };
  const d = normalizeInspect('docker', obj, 'sha256:abc');
  assert.equal(d.os, 'linux');
  assert.equal(d.architecture, 'amd64');
  assert.deepEqual(d.cmd, ['/bin/bash']);
  assert.equal(d.entrypoint, null);
  assert.deepEqual(d.env, ['PATH=/usr/bin', 'NODE_ENV=production']);
  assert.deepEqual(d.exposedPorts, ['80/tcp', '443/tcp']);
  assert.deepEqual(d.layers, ['sha256:layer1']);
  assert.deepEqual(d.labels, { 'org.opencontainers.image.vendor': 'openSUSE Project' });
});

test('normalizeInspect extracts crictl fields', () => {
  const obj = {
    info: {
      imageSpec: {
        architecture: 'amd64',
        os: 'linux',
        config: {
          Entrypoint: ['node', '/opt/osemapp/backend/index.js'],
          Env: ['PATH=/usr/bin', 'NODE_ENV=production'],
          ExposedPorts: { '3000/tcp': {}, '80/tcp': {} },
          Labels: { 'org.opencontainers.image.vendor': 'Mitel' },
        },
        rootfs: { type: 'layers', diff_ids: ['sha256:d7d4'] },
      },
    },
    status: { id: 'sha256:0a74' },
  };
  const d = normalizeInspect('crictl', obj, 'sha256:0a74');
  assert.equal(d.os, 'linux');
  assert.equal(d.architecture, 'amd64');
  assert.deepEqual(d.entrypoint, ['node', '/opt/osemapp/backend/index.js']);
  assert.equal(d.cmd, null);
  assert.deepEqual(d.exposedPorts, ['3000/tcp', '80/tcp']);
  assert.deepEqual(d.layers, ['sha256:d7d4']);
  assert.deepEqual(d.labels, { 'org.opencontainers.image.vendor': 'Mitel' });
});

test('normalizeInspect returns null for missing values', () => {
  const d = normalizeInspect('docker', { Id: 'x' }, 'x');
  assert.equal(d.os, null);
  assert.equal(d.architecture, null);
  assert.equal(d.labels, null);
  assert.equal(d.layers, null);
  assert.equal(d.entrypoint, null);
  assert.equal(d.cmd, null);
  assert.equal(d.env, null);
  assert.equal(d.exposedPorts, null);
});

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

// Generate a throwaway Ed25519 keypair once for all signature tests.
const { publicKey, privateKey } = generateKeyPairSync('ed25519');

/**
 * Sign the canonical layer message with the test private key and return the
 * base64-encoded signature (as it would appear in the image label).
 */
function signLayers(layers) {
  const message = computeLayerMessage(layers);
  return cryptoSign(null, message, privateKey).toString('base64');
}

test('computeLayerMessage produces deterministic hex-digest bytes', () => {
  const layers = ['sha256:a344a5d4ea4bb4e872c37f9f39277655edec697e9b6e430e2a5331b57a8810e8'];
  const msg = computeLayerMessage(layers);
  assert.equal(msg.length, 64, 'Ed25519 message must be 64 bytes (hex digest)');
  // The hex must match: sha256("sha256:a344...\n")
  const expected = createHash('sha256').update(`${layers[0]}\n`, 'utf8').digest('hex');
  assert.equal(msg.toString('utf8'), expected);
});

test('verifySignature returns "unsigned" when label is absent', () => {
  const result = verifySignature(null, ['sha256:aaa'], publicKey);
  assert.equal(result.status, 'unsigned');
  assert.equal(result.reason, undefined);
});

test('verifySignature returns "unsigned" for empty labels', () => {
  const result = verifySignature({}, ['sha256:aaa'], publicKey);
  assert.equal(result.status, 'unsigned');
});

test('verifySignature returns "valid" for a correctly signed image', () => {
  const layers = [
    'sha256:a344a5d4ea4bb4e872c37f9f39277655edec697e9b6e430e2a5331b57a8810e8',
  ];
  const sig = signLayers(layers);
  const result = verifySignature({ [SIGNATURE_LABEL]: sig }, layers, publicKey);
  assert.equal(result.status, 'valid');
});

test('verifySignature returns "valid" for multi-layer image', () => {
  const layers = ['sha256:aaa', 'sha256:bbb', 'sha256:ccc'];
  const sig = signLayers(layers);
  const result = verifySignature({ [SIGNATURE_LABEL]: sig }, layers, publicKey);
  assert.equal(result.status, 'valid');
});

test('verifySignature returns "invalid" when signature does not match layers', () => {
  const layers = ['sha256:aaa'];
  const tamperedLayers = ['sha256:bbb'];
  const sig = signLayers(layers);
  const result = verifySignature({ [SIGNATURE_LABEL]: sig }, tamperedLayers, publicKey);
  assert.equal(result.status, 'invalid');
  assert.ok(result.reason);
});

test('verifySignature returns "invalid" when public key is null', () => {
  const layers = ['sha256:aaa'];
  const sig = signLayers(layers);
  const result = verifySignature({ [SIGNATURE_LABEL]: sig }, layers, null);
  assert.equal(result.status, 'invalid');
  assert.ok(result.reason);
});

test('verifySignature returns "invalid" when layers are empty', () => {
  const sig = signLayers(['sha256:x']);
  const result = verifySignature({ [SIGNATURE_LABEL]: sig }, [], publicKey);
  assert.equal(result.status, 'invalid');
  assert.ok(result.reason);
});

test('verifySignature returns "invalid" for malformed base64 signature', () => {
  const result = verifySignature({ [SIGNATURE_LABEL]: '!!!not-base64!!!' }, ['sha256:x'], publicKey);
  // Buffer.from with 'base64' never throws; invalid chars are silently ignored,
  // so the sig will simply not verify.
  assert.equal(result.status, 'invalid');
  assert.ok(result.reason);
});

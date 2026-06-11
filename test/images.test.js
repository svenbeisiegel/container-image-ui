// test/images.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sign as cryptoSign, createHash, createPrivateKey, X509Certificate } from 'node:crypto';

import {
  parseDockerImages,
  parseCrictlImages,
  splitRepoTag,
  humanSizeToBytes,
  imageRef,
  normalizeDockerRepo,
  normalizeInspect,
  buildLayoutExportSteps,
  buildLayoutImportSteps,
  computeLayerMessage,
  verifySignature,
  verifyCertChain,
  splitPemCertificates,
  loadTrustedRoots,
  SIGNATURE_LABEL,
  CERTCHAIN_LABEL,
  EMBEDDED_ROOT_CA_PEM,
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

test('buildLayoutExportSteps copies docker images via the docker-daemon transport', () => {
  const { steps } = buildLayoutExportSteps({ engine: 'docker' }, 'nginx:1.25', '/tmp/layout', 'img0');
  assert.deepEqual(steps, [
    { bin: 'skopeo', args: ['copy', 'docker-daemon:nginx:1.25', 'oci:/tmp/layout:img0'] },
  ]);
});

test('buildLayoutExportSteps bridges containerd through ctr export', () => {
  const { steps } = buildLayoutExportSteps({ engine: 'crictl' }, 'nginx:1.25', '/tmp/layout', 'img2');
  assert.equal(steps.length, 2);
  assert.equal(steps[0].bin, 'ctr');
  assert.deepEqual(steps[0].args.slice(0, 4), ['-n', 'k8s.io', 'images', 'export']);
  const tmp = steps[0].args[4];
  assert.equal(steps[0].args[5], 'nginx:1.25');
  assert.deepEqual(steps[1], { bin: 'skopeo', args: ['copy', `oci-archive:${tmp}`, 'oci:/tmp/layout:img2'] });
});

test('buildLayoutExportSteps copies registry images via docker:// with TLS flags', () => {
  const caps = { engine: 'registry', registry: { host: 'h:5000', insecure: true } };
  const { steps } = buildLayoutExportSteps(caps, 'h:5000/app:1', '/tmp/layout', 'img0');
  assert.deepEqual(steps, [
    { bin: 'skopeo', args: ['copy', '--src-tls-verify=false', 'docker://h:5000/app:1', 'oci:/tmp/layout:img0'] },
  ]);
});

test('buildLayoutImportSteps loads docker images via the docker-daemon transport', () => {
  const { steps } = buildLayoutImportSteps({ engine: 'docker' }, 'oci:/tmp/layout:img0', 'nginx:1.25');
  assert.deepEqual(steps, [
    { bin: 'skopeo', args: ['copy', 'oci:/tmp/layout:img0', 'docker-daemon:nginx:1.25'] },
  ]);
});

test('buildLayoutImportSteps bridges containerd through ctr import', () => {
  const { steps } = buildLayoutImportSteps({ engine: 'crictl' }, 'oci:/tmp/layout:img0', 'nginx:1.25');
  assert.equal(steps.length, 2);
  // The ctr import step names the intermediate archive; the skopeo step writes it.
  assert.deepEqual(steps[1].args.slice(0, 4), ['-n', 'k8s.io', 'images', 'import']);
  const tmp = steps[1].args[4];
  assert.equal(steps[1].bin, 'ctr');
  assert.deepEqual(steps[0], { bin: 'skopeo', args: ['copy', 'oci:/tmp/layout:img0', `oci-archive:${tmp}:nginx:1.25`] });
});

test('buildLayoutImportSteps maps registry refs under our host', () => {
  const caps = { engine: 'registry', registry: { host: 'h:5000', insecure: false } };
  const { steps } = buildLayoutImportSteps(caps, 'oci:/tmp/layout:img0', 'docker.io/library/nginx:latest');
  assert.deepEqual(steps, [
    { bin: 'skopeo', args: ['copy', 'oci:/tmp/layout:img0', 'docker://h:5000/library/nginx:latest'] },
  ]);
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

test('normalizeInspect extracts registry config-blob fields', () => {
  // An OCI image config blob (what GET /v2/<repo>/blobs/<config-digest> returns).
  const obj = {
    architecture: 'amd64',
    os: 'linux',
    config: {
      Cmd: ['/bin/sh'],
      Env: ['PATH=/usr/bin'],
      ExposedPorts: { '8080/tcp': {} },
      Labels: { 'org.opencontainers.image.vendor': 'ACME' },
    },
    rootfs: { type: 'layers', diff_ids: ['sha256:aaa', 'sha256:bbb'] },
  };
  const d = normalizeInspect('registry', obj, 'sha256:digest');
  assert.equal(d.os, 'linux');
  assert.equal(d.architecture, 'amd64');
  assert.deepEqual(d.cmd, ['/bin/sh']);
  assert.deepEqual(d.exposedPorts, ['8080/tcp']);
  assert.deepEqual(d.layers, ['sha256:aaa', 'sha256:bbb']);
  assert.deepEqual(d.labels, { 'org.opencontainers.image.vendor': 'ACME' });
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
// Signature & certificate-chain verification
// ---------------------------------------------------------------------------

// Fixed Ed25519 fixtures generated with openssl: a self-signed root CA and a
// leaf certificate signed by it, plus the leaf's private key. Using fixtures
// (rather than generating certs at runtime) keeps the tests dependency-free.
const CA_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBqTCCAVugAwIBAgIURm/ss5EsgxhiDvnon0WVkAiILi0wBQYDK2VwMEExCzAJ
BgNVBAYTAkRFMQ0wCwYDVQQKDARUZXN0MQwwCgYDVQQLDANEZXYxFTATBgNVBAMM
DHRlc3Qtcm9vdC1jYTAgFw0yNjA2MTEwODU4MjBaGA8yMTI2MDUxODA4NTgyMFow
QTELMAkGA1UEBhMCREUxDTALBgNVBAoMBFRlc3QxDDAKBgNVBAsMA0RldjEVMBMG
A1UEAwwMdGVzdC1yb290LWNhMCowBQYDK2VwAyEA1ASLM2/ZCZnXmzZ4jQfQryN6
zgHhCkBsY9dBRHHC0AejYzBhMB0GA1UdDgQWBBTsQt2Co7uiJHe80mJXQy+8itAi
lzAfBgNVHSMEGDAWgBTsQt2Co7uiJHe80mJXQy+8itAilzAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQCidj4gPXmZaQlTHPr7lD0S3O/w
zYPm3T9a6R88qwML5PhJT3JTK1n7d7oXF8ZXrEQOTV46ZYk4VLK0RM1R4OgE
-----END CERTIFICATE-----`;

const LEAF_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCATegAwIBAgIUXwJnzEUVPbln9vIX4oX5xC6/hKgwBQYDK2VwMEExCzAJ
BgNVBAYTAkRFMQ0wCwYDVQQKDARUZXN0MQwwCgYDVQQLDANEZXYxFTATBgNVBAMM
DHRlc3Qtcm9vdC1jYTAgFw0yNjA2MTEwODU4MjBaGA8yMTI2MDUxODA4NTgyMFow
PjELMAkGA1UEBhMCREUxDTALBgNVBAoMBFRlc3QxDDAKBgNVBAsMA0RldjESMBAG
A1UEAwwJdGVzdC1sZWFmMCowBQYDK2VwAyEAEnbdwzLI40Sm+E/1WjrDnL7Ks2jV
OCf6dVCaSOazfgCjQjBAMB0GA1UdDgQWBBT0pfOhZ5alw6rjCr2wZIc6UKDdazAf
BgNVHSMEGDAWgBTsQt2Co7uiJHe80mJXQy+8itAilzAFBgMrZXADQQAmjAPUFToO
b6P5q6dMqzPH/g9JmODhYRjzK7wiUcnJOh+Cz4CU8x/Bl1w+WhA7EcyHN3mofKKD
zRyWOWvWYL8F
-----END CERTIFICATE-----`;

const LEAF_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIM3EK9IA/X4y8E7rnyIhBBxnMeGzJQrUJ39a2Uhey8XM
-----END PRIVATE KEY-----`;

const leafPrivateKey = createPrivateKey(LEAF_KEY_PEM);
const caCert = new X509Certificate(CA_CERT_PEM);
const trustedRoots = [caCert];
// The certchain label is the base64 of the (leaf-first) PEM bundle.
const CHAIN_B64 = Buffer.from(LEAF_CERT_PEM).toString('base64');

/** Sign the canonical layer message with the leaf private key (base64). */
function signLayers(layers) {
  const message = computeLayerMessage(layers);
  return cryptoSign(null, message, leafPrivateKey).toString('base64');
}

/** Build the label map for a signed image. */
function signedLabels(layers, { chain = CHAIN_B64 } = {}) {
  return { [SIGNATURE_LABEL]: signLayers(layers), [CERTCHAIN_LABEL]: chain };
}

test('computeLayerMessage produces deterministic hex-digest bytes', () => {
  const layers = ['sha256:a344a5d4ea4bb4e872c37f9f39277655edec697e9b6e430e2a5331b57a8810e8'];
  const msg = computeLayerMessage(layers);
  assert.equal(msg.length, 64, 'Ed25519 message must be 64 bytes (hex digest)');
  // The hex must match: sha256("sha256:a344...\n")
  const expected = createHash('sha256').update(`${layers[0]}\n`, 'utf8').digest('hex');
  assert.equal(msg.toString('utf8'), expected);
});

test('splitPemCertificates splits a bundle into individual certs', () => {
  const bundle = `${LEAF_CERT_PEM}\n${CA_CERT_PEM}\n`;
  const parts = splitPemCertificates(bundle);
  assert.equal(parts.length, 2);
  assert.ok(parts[0].includes('BEGIN CERTIFICATE'));
  assert.equal(splitPemCertificates('no certs here').length, 0);
});

test('verifyCertChain validates a leaf against its trusted root', () => {
  const leaf = new X509Certificate(LEAF_CERT_PEM);
  assert.deepEqual(verifyCertChain(leaf, [], trustedRoots), { ok: true });
});

test('verifyCertChain rejects a leaf with no trusted root', () => {
  const leaf = new X509Certificate(LEAF_CERT_PEM);
  const result = verifyCertChain(leaf, [], []);
  assert.equal(result.ok, false);
  assert.ok(result.reason);
});

test('verifyCertChain rejects a leaf that does not chain to the root', () => {
  const leaf = new X509Certificate(LEAF_CERT_PEM);
  // Use an unrelated CA (the embedded one) as the only trusted root.
  const unrelated = [new X509Certificate(EMBEDDED_ROOT_CA_PEM)];
  const result = verifyCertChain(leaf, [], unrelated);
  assert.equal(result.ok, false);
  assert.ok(result.reason);
});

test('verifySignature returns "unsigned" when label is absent', () => {
  const result = verifySignature(null, ['sha256:aaa'], trustedRoots);
  assert.equal(result.status, 'unsigned');
  assert.equal(result.reason, undefined);
});

test('verifySignature returns "unsigned" for empty labels', () => {
  const result = verifySignature({}, ['sha256:aaa'], trustedRoots);
  assert.equal(result.status, 'unsigned');
});

test('verifySignature returns "valid" for a correctly signed image', () => {
  const layers = ['sha256:a344a5d4ea4bb4e872c37f9f39277655edec697e9b6e430e2a5331b57a8810e8'];
  const result = verifySignature(signedLabels(layers), layers, trustedRoots);
  assert.equal(result.status, 'valid');
  assert.equal(result.signature, 'valid');
  assert.equal(result.chain, 'valid');
});

test('verifySignature works on a registry config blob (cross-backend parity)', () => {
  const layers = ['sha256:a344a5d4ea4bb4e872c37f9f39277655edec697e9b6e430e2a5331b57a8810e8'];
  // Simulate the registry path: a config blob with signing labels, normalized,
  // then verified — must match the docker/crictl result exactly.
  const configBlob = {
    architecture: 'amd64',
    os: 'linux',
    config: { Labels: signedLabels(layers) },
    rootfs: { type: 'layers', diff_ids: layers },
  };
  const d = normalizeInspect('registry', configBlob, 'sha256:digest');
  const result = verifySignature(d.labels, d.layers, trustedRoots);
  assert.equal(result.status, 'valid');
  assert.equal(result.signature, 'valid');
  assert.equal(result.chain, 'valid');
});

test('verifySignature returns "valid" for multi-layer image', () => {
  const layers = ['sha256:aaa', 'sha256:bbb', 'sha256:ccc'];
  const result = verifySignature(signedLabels(layers), layers, trustedRoots);
  assert.equal(result.status, 'valid');
});

test('verifySignature returns "invalid" when signature does not match layers', () => {
  const layers = ['sha256:aaa'];
  const tamperedLayers = ['sha256:bbb'];
  const result = verifySignature(signedLabels(layers), tamperedLayers, trustedRoots);
  assert.equal(result.status, 'invalid');
  assert.equal(result.signature, 'invalid');
  assert.ok(result.reason);
});

test('verifySignature returns "invalid" when the chain is not trusted', () => {
  const layers = ['sha256:aaa'];
  // Valid signature, but no trusted root that the leaf chains to.
  const result = verifySignature(signedLabels(layers), layers, [
    new X509Certificate(EMBEDDED_ROOT_CA_PEM),
  ]);
  assert.equal(result.status, 'invalid');
  assert.equal(result.signature, 'valid');
  assert.equal(result.chain, 'invalid');
  assert.ok(result.reason);
});

test('verifySignature returns "invalid" when certchain label is missing', () => {
  const layers = ['sha256:aaa'];
  const result = verifySignature({ [SIGNATURE_LABEL]: signLayers(layers) }, layers, trustedRoots);
  assert.equal(result.status, 'invalid');
  assert.ok(result.reason.includes(CERTCHAIN_LABEL));
});

test('verifySignature returns "invalid" when layers are empty', () => {
  const result = verifySignature(signedLabels(['sha256:x']), [], trustedRoots);
  assert.equal(result.status, 'invalid');
  assert.ok(result.reason);
});

test('verifySignature returns "invalid" for an unparseable certchain', () => {
  const layers = ['sha256:x'];
  const result = verifySignature(
    { [SIGNATURE_LABEL]: signLayers(layers), [CERTCHAIN_LABEL]: Buffer.from('not a cert').toString('base64') },
    layers,
    trustedRoots,
  );
  assert.equal(result.status, 'invalid');
  assert.ok(result.reason);
});

test('loadTrustedRoots falls back to the embedded CA', async () => {
  const roots = await loadTrustedRoots('');
  assert.ok(roots.length >= 1);
  assert.ok(roots[0] instanceof X509Certificate);
});

test('loadTrustedRoots falls back to embedded CA for an unreadable path', async () => {
  const roots = await loadTrustedRoots('/nonexistent/path/to/ca.pem');
  assert.ok(roots.length >= 1);
});

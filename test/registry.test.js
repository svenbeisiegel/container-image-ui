// test/registry.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  registryConfigFromEnv,
  parseRef,
  dockerRef,
  destRefForPull,
  inspectSize,
  buildCopyArgs,
  buildPullArgs,
  probe,
} from '../lib/registry.js';

test('registryConfigFromEnv parses a valid URL and credentials', () => {
  const cfg = registryConfigFromEnv({
    REGISTRY_URL: 'https://registry.example.com:5000/',
    REGISTRY_USERNAME: 'user',
    REGISTRY_PASSWORD: 'pass',
    REGISTRY_INSECURE: '1',
  });
  assert.equal(cfg.base, 'https://registry.example.com:5000');
  assert.equal(cfg.host, 'registry.example.com:5000');
  assert.equal(cfg.username, 'user');
  assert.equal(cfg.password, 'pass');
  assert.equal(cfg.insecure, true);
});

test('registryConfigFromEnv returns null when unset or invalid', () => {
  assert.equal(registryConfigFromEnv({}), null);
  assert.equal(registryConfigFromEnv({ REGISTRY_URL: '   ' }), null);
  assert.equal(registryConfigFromEnv({ REGISTRY_URL: 'ftp://nope' }), null);
  assert.equal(registryConfigFromEnv({ REGISTRY_URL: 'not a url' }), null);
});

test('parseRef strips the host and splits tag vs digest', () => {
  const cfg = { host: 'registry.example.com:5000' };
  assert.deepEqual(parseRef(cfg, 'registry.example.com:5000/team/app:v1'), {
    repoPath: 'team/app',
    reference: 'v1',
  });
  assert.deepEqual(parseRef(cfg, 'team/app@sha256:deadbeef'), {
    repoPath: 'team/app',
    reference: 'sha256:deadbeef',
  });
  assert.deepEqual(parseRef(cfg, 'team/app'), { repoPath: 'team/app', reference: 'latest' });
  assert.deepEqual(parseRef({ host: 'localhost:5000' }, 'localhost:5000/app:1.0'), {
    repoPath: 'app',
    reference: '1.0',
  });
});

test('dockerRef ensures the registry host prefix (idempotent)', () => {
  const cfg = { host: 'h:5000' };
  assert.equal(dockerRef(cfg, 'a/b:1'), 'h:5000/a/b:1');
  assert.equal(dockerRef(cfg, 'h:5000/a/b:1'), 'h:5000/a/b:1');
});

test('destRefForPull maps a source ref under our host, stripping its registry', () => {
  const cfg = { host: 'h:5000' };
  assert.equal(destRefForPull(cfg, 'docker.io/library/nginx:latest'), 'h:5000/library/nginx:latest');
  assert.equal(destRefForPull(cfg, 'nginx:latest'), 'h:5000/nginx:latest');
  assert.equal(destRefForPull(cfg, 'localhost:5000/app:1'), 'h:5000/app:1');
});

test('inspectSize sums LayersData sizes', () => {
  assert.equal(inspectSize({ LayersData: [{ Size: 100 }, { Size: 200 }] }), 300);
  assert.equal(inspectSize({}), 0);
  assert.equal(inspectSize(null), 0);
});

test('buildCopyArgs applies TLS flags only to our-registry endpoints', () => {
  const cfg = { host: 'h:5000', insecure: true };
  // download: source is ours, dest is a local archive.
  assert.deepEqual(
    buildCopyArgs(cfg, 'docker://h:5000/a:1', 'docker-archive:/tmp/x.tar:h:5000/a:1'),
    ['copy', '--src-tls-verify=false', 'docker://h:5000/a:1', 'docker-archive:/tmp/x.tar:h:5000/a:1'],
  );
  // secure registry: no TLS flags added.
  assert.deepEqual(
    buildCopyArgs({ host: 'h:5000', insecure: false }, 'docker://h:5000/a:1', 'docker-archive:/tmp/x.tar:a'),
    ['copy', 'docker://h:5000/a:1', 'docker-archive:/tmp/x.tar:a'],
  );
});

test('buildPullArgs copies a source ref into our registry', () => {
  const cfg = { host: 'h:5000', insecure: true };
  assert.deepEqual(buildPullArgs(cfg, 'docker.io/library/nginx:latest'), [
    'copy',
    '--dest-tls-verify=false',
    'docker://docker.io/library/nginx:latest',
    'docker://h:5000/library/nginx:latest',
  ]);
});

test('probe resolves false for an unreachable registry', async () => {
  // Reserved TEST-NET-1 address; connection should fail fast, not hang.
  const cfg = registryConfigFromEnv({ REGISTRY_URL: 'http://192.0.2.1:5000' });
  assert.equal(await probe(cfg), false);
});

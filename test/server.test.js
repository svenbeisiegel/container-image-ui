// test/server.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { decompressorFor, isValidRef } from '../server.js';

test('decompressorFor selects the right tool per extension', () => {
  assert.equal(decompressorFor('image.tar'), null);
  assert.deepEqual(decompressorFor('image.tar.gz'), { bin: 'gzip', args: ['-d', '-c'] });
  assert.deepEqual(decompressorFor('image.tgz'), { bin: 'gzip', args: ['-d', '-c'] });
  assert.deepEqual(decompressorFor('image.tar.xz'), { bin: 'xz', args: ['-d', '-c'] });
  assert.equal(decompressorFor('image.zip'), undefined);
  assert.equal(decompressorFor('image'), undefined);
});

test('isValidRef accepts legitimate image references and ids', () => {
  assert.equal(isValidRef('alpine:latest'), true);
  assert.equal(isValidRef('docker.io/osem/couchdb:3.5.2-r0-tumbleweed'), true);
  assert.equal(isValidRef('registry.example.com:5000/team/app:v1'), true);
  assert.equal(isValidRef('sha256:abc123'), true);
  assert.equal(isValidRef('img@sha256:deadbeef'), true);
});

test('isValidRef rejects option-injection and malformed input', () => {
  assert.equal(isValidRef('-o/tmp/evil'), false); // leading dash -> looks like a flag
  assert.equal(isValidRef('--output=/etc/passwd'), false);
  assert.equal(isValidRef(''), false);
  assert.equal(isValidRef('a\nb'), false); // newline / SSE-frame injection
  assert.equal(isValidRef('a\tb'), false); // control char
  assert.equal(isValidRef(42), false); // non-string
  assert.equal(isValidRef('a'.repeat(513)), false); // too long
});

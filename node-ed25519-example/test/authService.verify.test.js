import assert from 'node:assert/strict';
import { test } from 'node:test';
import { v7 as uuidv7 } from 'uuid';
import { verifyRequestFromHeaders } from '../src/http/verifyRequest.js';
import * as testKeys from './testKeys.js';

const authService = testKeys.newAuthService();

function nonceAt(unixMilli) {
  return uuidv7({ msecs: unixMilli });
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function signedRequest({
  body = '{"amount":100}',
  data = body,
  payloadDomain = 'five-gaming',
  headerDomain = 'five-gaming',
  nonce = nonceAt(Date.now()),
  notBefore = nowSeconds() - 60,
  notAfter = nowSeconds() + 3600,
  root = testKeys.rootKey,
  payloadSigner,
  rawPayload,
} = {}) {
  const intermediate = testKeys.randomKey();
  const intermediatePublicKey = testKeys.rawPublicKey(intermediate).toString('base64');
  const certificate = `{"not_after":${notAfter},"not_before":${notBefore},"public_key":"${intermediatePublicKey}"}`;

  const payload =
    rawPayload === undefined
      ? Buffer.from(JSON.stringify({ data, domain: payloadDomain, nonce }), 'utf8')
      : Buffer.from(rawPayload.replaceAll('NONCE', nonce), 'latin1');

  return {
    body: Buffer.from(body, 'utf8'),
    headers: {
      'x-sign-version': ['2'],
      'x-sign-domain': [headerDomain],
      'x-sign-nonce': [nonce],
      'x-sign-payload': [payload.toString('latin1')],
      'x-sign-signature': [testKeys.sign(payloadSigner ?? intermediate, payload).toString('base64')],
      'x-sign-intermediate-public-key': [intermediatePublicKey],
      'x-sign-intermediate-signature': [testKeys.sign(root, Buffer.from(certificate, 'utf8')).toString('base64')],
      'x-sign-intermediate-not-before': [String(notBefore)],
      'x-sign-intermediate-not-after': [String(notAfter)],
    },
  };
}

function withHeaders(headers, overrides) {
  const result = { ...headers };
  for (const [name, override] of Object.entries(overrides)) {
    if (override === undefined) {
      delete result[name];
      continue;
    }

    const value = typeof override === 'function' ? override(headers[name][0]) : override;
    result[name] = Array.isArray(value) ? value : [value];
  }
  return result;
}

function verify(options = {}, headerOverrides = {}) {
  const { headers, body } = signedRequest(options);
  return authService.verify(verifyRequestFromHeaders(withHeaders(headers, headerOverrides)), body);
}

function nestedPayload(depth) {
  const arrays = depth - 1;
  return `{"data":"{\\"amount\\":100}","domain":"five-gaming","nonce":"NONCE","x":${'['.repeat(arrays)}${']'.repeat(arrays)}}`;
}

test('valid request', () => assert.equal(verify(), true));

test('unicode body with raw UTF-8 payload', () =>
  assert.equal(verify({ body: '{"name":"Joë’s Café — €5","emoji":"🎰"}' }), true));

test('empty body', () => assert.equal(verify({ body: '' }), true));

test('nonce slightly in future within clock skew', () => assert.equal(verify({ nonce: nonceAt(Date.now() + 30_000) }), true));

test('replayed request', () => {
  const { headers, body } = signedRequest();

  assert.equal(authService.verify(verifyRequestFromHeaders(headers), body), true);
  assert.equal(authService.verify(verifyRequestFromHeaders(headers), body), false);
});

test('tampered body', () => {
  const { headers } = signedRequest();

  assert.equal(authService.verify(verifyRequestFromHeaders(headers), Buffer.from('{"amount":999}')), false);
});

test('no headers at all', () => assert.equal(authService.verify(verifyRequestFromHeaders({}), Buffer.alloc(0)), false));

test('direct caller passing an empty request', () => assert.equal(authService.verify({}, Buffer.alloc(0)), false));

test('wrong version', () => assert.equal(verify({}, { 'x-sign-version': '1' }), false));

test('duplicated header', () =>
  assert.equal(verify({}, { 'x-sign-signature': (signature) => [signature, signature] }), false));

test('missing signature', () => assert.equal(verify({}, { 'x-sign-signature': undefined }), false));

test('signature not base64', () => assert.equal(verify({}, { 'x-sign-signature': 'not-base64!!' }), false));

test('signature wrong length', () =>
  assert.equal(verify({}, { 'x-sign-signature': Buffer.alloc(63).toString('base64') }), false));

test('payload signed by other key', () => assert.equal(verify({ payloadSigner: testKeys.randomKey() }), false));

test('certificate signed by other root', () => assert.equal(verify({ root: testKeys.randomKey() }), false));

test('certificate validity extended after signing', () =>
  assert.equal(verify({}, { 'x-sign-intermediate-not-after': '9999999999' }), false));

test('certificate not-after not a number', () => assert.equal(verify({}, { 'x-sign-intermediate-not-after': 'soon' }), false));

test('certificate expired', () => assert.equal(verify({ notAfter: nowSeconds() - 1 }), false));

test('certificate not yet valid', () => assert.equal(verify({ notBefore: nowSeconds() + 600 }), false));

test('missing payload', () => assert.equal(verify({}, { 'x-sign-payload': undefined }), false));

test('payload not JSON', () => assert.equal(verify({ rawPayload: 'not json' }), false));

test('payload is JSON array', () => assert.equal(verify({ rawPayload: '[1,2]' }), false));

test('data is not a string', () => assert.equal(verify({ data: 100 }), false));

test('payload domain mismatch', () => assert.equal(verify({ payloadDomain: 'evil' }), false));

test('header domain mismatch', () => assert.equal(verify({ headerDomain: 'evil' }), false));

test('nonce header mismatch', () => assert.equal(verify({}, { 'x-sign-nonce': nonceAt(Date.now()) }), false));

test('nonce too old', () => assert.equal(verify({ nonce: nonceAt(Date.now() - 6 * 60_000) }), false));

test('nonce too far in future', () => assert.equal(verify({ nonce: nonceAt(Date.now() + 2 * 60_000) }), false));

test('nonce too short', () => assert.equal(verify({ nonce: 'abc' }), false));

test('nonce not hex', () => assert.equal(verify({ nonce: 'zzzzzzzz-zzzz-7zzz-8zzz-zzzzzzzzzzzz' }), false));

test('payload keys differ in case', () =>
  assert.equal(verify({ rawPayload: '{"DATA":"{\\"amount\\":100}","Domain":"five-gaming","Nonce":"NONCE"}' }), false));

test('valid surrogate pair in data', () =>
  assert.equal(
    verify({ body: '\u{1F680}', rawPayload: '{"data":"\\ud83d\\ude80","domain":"five-gaming","nonce":"NONCE"}' }),
    true,
  ));

test('lone low surrogate in data', () =>
  assert.equal(verify({ body: '\uFFFD', rawPayload: '{"data":"\\udcff","domain":"five-gaming","nonce":"NONCE"}' }), false));

test('lone surrogate in an unused key', () =>
  assert.equal(
    verify({ rawPayload: '{"data":"{\\"amount\\":100}","domain":"five-gaming","nonce":"NONCE","x":"\\udcff"}' }),
    false,
  ));

test('invalid UTF-8 byte in payload', () =>
  assert.equal(verify({ body: '\uFFFD', rawPayload: '{"data":"\xff","domain":"five-gaming","nonce":"NONCE"}' }), false));

test('payload starts with a byte order mark', () =>
  assert.equal(
    verify({ rawPayload: '\xEF\xBB\xBF{"data":"{\\"amount\\":100}","domain":"five-gaming","nonce":"NONCE"}' }),
    false,
  ));

test('not-before with a plus sign', () =>
  assert.equal(verify({}, { 'x-sign-intermediate-not-before': (notBefore) => '+' + notBefore }), false));

test('signature base64 with a space inside', () =>
  assert.equal(verify({}, { 'x-sign-signature': (signature) => signature.replace(/^(.{4})/, '$1 ') }), false));

test('signature base64 without padding', () =>
  assert.equal(verify({}, { 'x-sign-signature': (signature) => signature.replace(/=+$/, '') }), false));

test('payload nested 64 levels deep', () => assert.equal(verify({ rawPayload: nestedPayload(64) }), true));

test('payload nested 65 levels deep', () => assert.equal(verify({ rawPayload: nestedPayload(65) }), false));

test('brackets inside strings do not count as nesting', () =>
  assert.equal(verify({ body: '['.repeat(100) + '\\"' + '{'.repeat(100) }), true));

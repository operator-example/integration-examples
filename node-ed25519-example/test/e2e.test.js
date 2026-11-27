import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { v7 as uuidv7 } from 'uuid';
import { AuthService } from '../src/services/authService.js';
import { baseUrlOf, startServer, stopServer } from './testServer.js';

const DOMAIN = 'five-gaming';

const rootKeys = crypto.generateKeyPairSync('ed25519');
const intermediateKeys = crypto.generateKeyPairSync('ed25519');
const operatorKeys = crypto.generateKeyPairSync('ed25519');

let server;
let baseUrl;

before(async () => {
  const authService = new AuthService({
    keyId: 'test-key',
    operatorId: 'test-operator',
    privateKey: rawKey(operatorKeys.privateKey, 'd').toString('base64'),
    rootPublicKey: rawKey(rootKeys.publicKey, 'x').toString('base64'),
  });
  server = await startServer(authService);
  baseUrl = baseUrlOf(server);
});

after(() => stopServer(server));

describe('POST /Auth/sign', () => {
  test('returned signature verifies with the matching public key', async () => {
    const body = '{"msg":"café ✓ 🚀 hi"}';
    const response = await fetch(`${baseUrl}/sign`, { method: 'POST', body });
    assert.equal(response.status, 200);

    const result = await response.json();
    assert.equal(result.key_id, 'test-key');
    assert.equal(result.operator_id, 'test-operator');
    assert.match(result.payload, /^[\x00-\x7f]*$/, 'payload must be pure ASCII');
    assert.equal(JSON.parse(result.payload).data, body);
    assert.equal(
      crypto.verify(null, Buffer.from(result.payload, 'ascii'), operatorKeys.publicKey, Buffer.from(result.signature, 'base64')),
      true,
    );
  });

  test('nonce is a UUIDv7 with a timestamp close to now (seconds)', async () => {
    const response = await fetch(`${baseUrl}/sign`, { method: 'POST', body: 'x' });
    const { nonce } = JSON.parse((await response.json()).payload);
    assert.match(nonce, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

    const nonceSeconds = Math.floor(Number('0x' + nonce.slice(0, 8) + nonce.slice(9, 13)) / 1000);
    assert.ok(Math.abs(nonceSeconds - nowSeconds()) <= 2);
  });
});

describe('POST /Auth/verify', () => {
  test('valid request passes', async () => {
    assert.equal(await verify(), 200);
  });

  test('replayed nonce is rejected', async () => {
    const request = buildVerifyRequest();
    assert.equal(await send(request), 200);
    assert.equal(await send(request), 401);
  });

  test('tampered body is rejected', async () => {
    const request = buildVerifyRequest({ body: 'hello' });
    assert.equal(await send({ ...request, body: 'hellO' }), 401);
  });

  test('invalid signature is rejected', async () => {
    const request = buildVerifyRequest();
    request.headers['X-Sign-Signature'] = Buffer.alloc(64).toString('base64');
    assert.equal(await send(request), 401);
  });

  test('intermediate certificate not signed by root is rejected', async () => {
    const request = buildVerifyRequest({ certificateSigner: crypto.generateKeyPairSync('ed25519').privateKey });
    assert.equal(await send(request), 401);
  });

  test('mismatched domain is rejected', async () => {
    assert.equal(await verify({ domain: 'other-domain' }), 401);
  });

  test('missing header is rejected', async () => {
    const request = buildVerifyRequest();
    delete request.headers['X-Sign-Nonce'];
    assert.equal(await send(request), 401);
  });

  describe('nonce time window (max age 5 minutes, clock skew 60 seconds)', () => {
    test('4 minutes ago: passes', async () => {
      assert.equal(await verify({ nonceMs: Date.now() - 4 * 60_000 }), 200);
    });

    test('6 minutes ago: rejected', async () => {
      assert.equal(await verify({ nonceMs: Date.now() - 6 * 60_000 }), 401);
    });

    test('30 seconds ahead: passes', async () => {
      assert.equal(await verify({ nonceMs: Date.now() + 30_000 }), 200);
    });

    test('2 minutes ahead: rejected', async () => {
      assert.equal(await verify({ nonceMs: Date.now() + 120_000 }), 401);
    });
  });

  describe('intermediate certificate validity period (Unix seconds)', () => {
    test('valid within ±10 seconds: passes', async () => {
      const now = nowSeconds();
      assert.equal(await verify({ notBefore: now - 10, notAfter: now + 10 }), 200);
    });

    test('expired 10 seconds ago: rejected', async () => {
      const now = nowSeconds();
      assert.equal(await verify({ notBefore: now - 3600, notAfter: now - 10 }), 401);
    });

    test('not valid until 10 seconds from now: rejected', async () => {
      const now = nowSeconds();
      assert.equal(await verify({ notBefore: now + 10, notAfter: now + 3600 }), 401);
    });

    test('milliseconds used by mistake: rejected', async () => {
      const now = nowSeconds();
      assert.equal(await verify({ notBefore: (now - 60) * 1000, notAfter: (now + 3600) * 1000 }), 401);
    });
  });
});

function buildVerifyRequest({
  body = 'hello',
  domain = DOMAIN,
  nonceMs = Date.now(),
  notBefore = nowSeconds() - 60,
  notAfter = nowSeconds() + 3600,
  certificateSigner = rootKeys.privateKey,
} = {}) {
  const intermediatePublicKey = rawKey(intermediateKeys.publicKey, 'x').toString('base64');
  const certificate = `{"not_after":${notAfter},"not_before":${notBefore},"public_key":"${intermediatePublicKey}"}`;
  const nonce = uuidv7({ msecs: nonceMs });
  const payload = JSON.stringify({ data: body, domain, nonce });

  return {
    body,
    headers: {
      'X-Sign-Version': '2',
      'X-Sign-Intermediate-Public-Key': intermediatePublicKey,
      'X-Sign-Intermediate-Signature': crypto.sign(null, Buffer.from(certificate), certificateSigner).toString('base64'),
      'X-Sign-Intermediate-Not-Before': String(notBefore),
      'X-Sign-Intermediate-Not-After': String(notAfter),
      'X-Sign-Signature': crypto.sign(null, Buffer.from(payload), intermediateKeys.privateKey).toString('base64'),
      'X-Sign-Payload': payload,
      'X-Sign-Nonce': nonce,
      'X-Sign-Domain': domain,
    },
  };
}

async function send({ body, headers }) {
  const response = await fetch(`${baseUrl}/verify`, { method: 'POST', body, headers });
  await response.arrayBuffer();
  return response.status;
}

function verify(options) {
  return send(buildVerifyRequest(options));
}

function rawKey(keyObject, field) {
  return Buffer.from(keyObject.export({ format: 'jwk' })[field], 'base64url');
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

describe('error responses are JSON, never HTML or stack traces', () => {
  const MAX_BODY_SIZE = 8 * 1024 * 1024;

  test('sign with invalid UTF-8: 400', async () => {
    const response = await fetch(`${baseUrl}/sign`, { method: 'POST', body: Buffer.from([0xff]) });
    assert.equal(response.status, 400);
    assert.match(response.headers.get('content-type'), /^application\/json/);
    assert.deepEqual(await response.json(), { error: 'body is not valid UTF-8' });
  });

  for (const path of ['sign', 'verify']) {
    test(`${path} with a body over 8 MiB: 413`, async () => {
      const response = await fetch(`${baseUrl}/${path}`, { method: 'POST', body: Buffer.alloc(MAX_BODY_SIZE + 1, 'a') });
      assert.equal(response.status, 413);
      assert.deepEqual(await response.json(), { error: 'body is too large' });
    });
  }

  test('sign with a body of exactly 8 MiB: 200', async () => {
    const response = await fetch(`${baseUrl}/sign`, { method: 'POST', body: Buffer.alloc(MAX_BODY_SIZE, 'a') });
    assert.equal(response.status, 200);
  });
});

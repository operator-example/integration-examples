import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';
import { InvalidBodyError } from '../src/services/authService.js';
import * as testKeys from './testKeys.js';

const authService = testKeys.newAuthService();

const { cases } = JSON.parse(readFileSync(new URL('../../testdata/payload-escaping-cases.json', import.meta.url), 'utf8'));

describe('AuthService.sign', () => {
  test('payload cases file has more than 100 cases', () => {
    assert.ok(cases.length > 100);
  });

  describe('payload passes AuthService', () => {
    for (const { name, bodyHex, expectedData, rejected } of cases) {
      test(name, () => {
        const body = Buffer.from(bodyHex, 'hex');
        if (rejected) {
          assert.throws(() => authService.sign(body), InvalidBodyError);
          return;
        }

        const signed = authService.sign(body);

        assert.match(signed.payload, /^[\x20-\x7e]*$/);
        assert.equal(signed.payload.slice(0, signed.payload.indexOf(',"nonce":')), `{"data":"${expectedData}"`);
        assert.equal(JSON.parse(signed.payload).data, body.toString('utf8'));
        assertSignedByOperator(signed);
      });
    }
  });

  test('returns configured ids', () => {
    const signed = authService.sign(Buffer.from('{}'));

    assert.equal(signed.keyId, testKeys.KEY_ID);
    assert.equal(signed.operatorId, testKeys.OPERATOR_ID);
  });

  test('nonce is current UUIDv7', () => {
    const before = Date.now();
    const signed = authService.sign(Buffer.alloc(0));
    const after = Date.now();

    const nonce = signed.payload.match(/"nonce":"([^"]+)"/)[1];
    assert.match(nonce, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    const unixMilli = Number('0x' + nonce.slice(0, 8) + nonce.slice(9, 13));
    assert.ok(unixMilli >= before && unixMilli <= after);
  });

  test('every signature uses a fresh nonce', () => {
    const body = Buffer.from('same');

    assert.notEqual(authService.sign(body).payload, authService.sign(body).payload);
  });
});

function assertSignedByOperator(signed) {
  const payload = Buffer.from(signed.payload, 'ascii');
  assert.equal(testKeys.verify(testKeys.operatorKey, payload, Buffer.from(signed.signature, 'base64')), true);
}

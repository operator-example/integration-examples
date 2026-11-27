import crypto from 'node:crypto';
import { AuthService } from '../src/services/authService.js';

export const KEY_ID = 'test-key';
export const OPERATOR_ID = 'test-operator';
export const operatorKey = keyFromSeed(1);
export const rootKey = keyFromSeed(2);

export function config() {
  return {
    keyId: KEY_ID,
    operatorId: OPERATOR_ID,
    privateKey: rawPrivateKey(operatorKey).toString('base64'),
    rootPublicKey: rawPublicKey(rootKey).toString('base64'),
  };
}

export function newAuthService() {
  return new AuthService(config());
}

export function randomKey() {
  return crypto.generateKeyPairSync('ed25519').privateKey;
}

export function sign(privateKey, data) {
  return crypto.sign(null, data, privateKey);
}

export function verify(privateKey, data, signature) {
  return crypto.verify(null, data, crypto.createPublicKey(privateKey), signature);
}

export function rawPublicKey(privateKey) {
  return Buffer.from(crypto.createPublicKey(privateKey).export({ format: 'jwk' }).x, 'base64url');
}

function rawPrivateKey(privateKey) {
  return Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
}

function keyFromSeed(value) {
  return crypto.createPrivateKey({
    key: Buffer.alloc(32, value),
    format: 'raw-private',
    asymmetricKeyType: 'ed25519',
  });
}

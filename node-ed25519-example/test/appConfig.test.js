import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { getConfigErrors, loadConfig } from '../src/config/appConfig.js';
import { AuthService } from '../src/services/authService.js';
import * as testKeys from './testKeys.js';
import { baseUrlOf, startServer, stopServer } from './testServer.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));
const VALID_KEY = Buffer.alloc(32).toString('base64');

function config({ keyId = 'key', operatorId = 'operator', privateKey = VALID_KEY, rootPublicKey = VALID_KEY } = {}) {
  return { keyId, operatorId, privateKey, rootPublicKey };
}

test('valid config has no errors', () => {
  assert.deepEqual(getConfigErrors(config()), []);
});

test('reports every missing setting at once', () => {
  const errors = getConfigErrors(config({ keyId: '', operatorId: ' ', privateKey: '', rootPublicKey: '' }));

  assert.deepEqual(errors, [
    'KEY_ID is not set',
    'OPERATOR_ID is not set',
    'PRIVATE_KEY is not set',
    'ROOT_PUBLIC_KEY is not set',
  ]);
});

test('rejects invalid base64', () => {
  assert.deepEqual(getConfigErrors(config({ privateKey: 'not base64!!' })), ['PRIVATE_KEY is not valid base64']);
});

test('rejects wrong key length', () => {
  const errors = getConfigErrors(config({ rootPublicKey: Buffer.alloc(31).toString('base64') }));

  assert.deepEqual(errors, ['ROOT_PUBLIC_KEY must be a 32-byte raw Ed25519 key, got 31 bytes']);
});

test('rejects PKCS#8 instead of raw key', () => {
  const errors = getConfigErrors(config({ privateKey: Buffer.alloc(48).toString('base64') }));

  assert.deepEqual(errors, ['PRIVATE_KEY must be a 32-byte raw Ed25519 key, got 48 bytes']);
});

test('error message never contains the secret', () => {
  const secret = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).toString('base64');

  for (const error of getConfigErrors(config({ privateKey: secret }))) {
    assert.equal(error.includes(secret), false);
  }
});

test('loadConfig reads every setting from the environment', () => {
  assert.deepEqual(
    loadConfig({ KEY_ID: 'key', OPERATOR_ID: 'operator', PRIVATE_KEY: 'private', ROOT_PUBLIC_KEY: 'root', PORT: '9000' }),
    { keyId: 'key', operatorId: 'operator', privateKey: 'private', rootPublicKey: 'root', port: 9000 },
  );
});

test('loadConfig defaults missing settings', () => {
  assert.deepEqual(loadConfig({}), { keyId: '', operatorId: '', privateKey: '', rootPublicKey: '', port: 8080 });
});

test('app starts with valid config', async (t) => {
  const valid = testKeys.config();
  const appConfig = loadConfig({
    KEY_ID: valid.keyId,
    OPERATOR_ID: valid.operatorId,
    PRIVATE_KEY: valid.privateKey,
    ROOT_PUBLIC_KEY: valid.rootPublicKey,
  });
  assert.deepEqual(getConfigErrors(appConfig), []);

  const server = await startServer(new AuthService(appConfig));
  t.after(() => stopServer(server));

  const response = await fetch(`${baseUrlOf(server)}/sign`, { method: 'POST', body: '{}' });
  assert.equal(response.status, 200);
});

test('app refuses to start with bad config', async () => {
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      PORT: '0',
      KEY_ID: 'key',
      OPERATOR_ID: 'operator',
      PRIVATE_KEY: Buffer.alloc(48).toString('base64'),
      ROOT_PUBLIC_KEY: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  child.stderr.on('data', (chunk) => (stderr += chunk));
  const [exitCode] = await once(child, 'exit');

  assert.equal(exitCode, 1);
  assert.equal(
    stderr,
    'Invalid configuration:\n' +
      '  - PRIVATE_KEY must be a 32-byte raw Ed25519 key, got 48 bytes\n' +
      '  - ROOT_PUBLIC_KEY is not set\n',
  );
});

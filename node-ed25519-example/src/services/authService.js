import { isUtf8 } from 'node:buffer';
import crypto from 'node:crypto';
import { v7 as uuidv7 } from 'uuid';

const EXPECTED_DOMAIN = 'five-gaming';
const NONCE_MAX_AGE_SECONDS = 5 * 60;
const CLOCK_SKEW_SECONDS = 60;
const MAX_PAYLOAD_DEPTH = 64;

export class InvalidBodyError extends Error {
  name = 'InvalidBodyError';
  status = 400;
  expose = true;
}

export class AuthService {
  #usedNonces = new Map();
  #nonceExpiry = [];
  #keyId;
  #operatorId;
  #privateKey;
  #rootPublicKey;

  constructor(config) {
    this.#keyId = config.keyId;
    this.#operatorId = config.operatorId;
    this.#privateKey = crypto.createPrivateKey({
      key: Buffer.from(config.privateKey, 'base64'),
      format: 'raw-private',
      asymmetricKeyType: 'ed25519',
    });
    this.#rootPublicKey = Buffer.from(config.rootPublicKey, 'base64');
  }

  sign(body) {
    if (!isUtf8(body)) {
      throw new InvalidBodyError('body is not valid UTF-8');
    }

    const data = body.toString('utf8');
    const nonce = uuidv7();
    const payload = buildPayload(data, nonce);
    const signature = crypto.sign(null, Buffer.from(payload, 'ascii'), this.#privateKey);

    return {
      keyId: this.#keyId,
      operatorId: this.#operatorId,
      payload,
      signature: signature.toString('base64'),
    };
  }

  verify(request, body) {
    if (request.version !== '2') {
      return false;
    }

    const intermediatePublicKey = decodeFromBase64(request.intermediatePublicKey, 32);
    if (intermediatePublicKey === undefined) {
      return false;
    }

    const intermediateSignature = decodeFromBase64(request.intermediateSignature, 64);
    if (intermediateSignature === undefined) {
      return false;
    }

    const signature = decodeFromBase64(request.signature, 64);
    if (signature === undefined) {
      return false;
    }

    const notBefore = parseInteger(request.intermediateNotBefore);
    if (notBefore === undefined) {
      return false;
    }

    const notAfter = parseInteger(request.intermediateNotAfter);
    if (notAfter === undefined) {
      return false;
    }

    const now = Math.floor(Date.now() / 1000);
    const certificate = `{"not_after":${notAfter},"not_before":${notBefore},"public_key":"${intermediatePublicKey.toString('base64')}"}`;
    if (!ed25519Verify(intermediateSignature, this.#rootPublicKey, Buffer.from(certificate, 'utf8'))) {
      return false;
    }

    if (now < notBefore || now > notAfter) {
      return false;
    }

    if (typeof request.payload !== 'string') {
      return false;
    }

    const payload = Buffer.from(request.payload, 'latin1');
    if (!ed25519Verify(signature, intermediatePublicKey, payload)) {
      return false;
    }

    let document;
    try {
      document = parsePayload(payload);
    } catch {
      return false;
    }

    if (document === null || typeof document !== 'object' || Array.isArray(document)) {
      return false;
    }

    if (typeof document.domain !== 'string' || document.domain !== EXPECTED_DOMAIN) {
      return false;
    }

    if (typeof document.nonce !== 'string' || document.nonce !== request.nonce) {
      return false;
    }

    if (typeof document.data !== 'string' || !Buffer.from(document.data, 'utf8').equals(body)) {
      return false;
    }

    if (request.domain !== EXPECTED_DOMAIN) {
      return false;
    }

    if (!isNonceInTimeWindow(document.nonce, now)) {
      return false;
    }

    return this.#tryMarkNonceUsed(document.nonce, now);
  }

  #tryMarkNonceUsed(nonce, now) {
    let expiredCount = 0;
    while (expiredCount < this.#nonceExpiry.length && this.#nonceExpiry[expiredCount].expiresAt < now) {
      this.#usedNonces.delete(this.#nonceExpiry[expiredCount].nonce);
      expiredCount++;
    }
    this.#nonceExpiry.splice(0, expiredCount);

    if (this.#usedNonces.has(nonce)) {
      return false;
    }

    const expiresAt = now + NONCE_MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS;
    this.#usedNonces.set(nonce, expiresAt);
    this.#nonceExpiry.push({ nonce, expiresAt });
    return true;
  }
}

function buildPayload(data, nonce) {
  return `{"data":${toJsonString(data)},"nonce":${toJsonString(nonce)}}`;
}

const SHORT_ESCAPES = { '\\': '\\\\', '\b': '\\b', '\t': '\\t', '\n': '\\n', '\f': '\\f', '\r': '\\r' };

function toJsonString(value) {
  const escaped = value.replace(
    /[\u0000-\u001f"&'+<>\\`\u007f-\uffff]/g,
    (character) =>
      SHORT_ESCAPES[character] ?? '\\u' + character.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'),
  );
  return `"${escaped}"`;
}

function parsePayload(payload) {
  if (!isUtf8(payload)) {
    throw new Error('payload is not valid UTF-8');
  }

  const text = payload.toString('utf8');
  if (exceedsDepth(text, MAX_PAYLOAD_DEPTH)) {
    throw new Error('payload is nested too deeply');
  }

  return JSON.parse(text, (key, value) => {
    if (!key.isWellFormed() || (typeof value === 'string' && !value.isWellFormed())) {
      throw new Error('payload contains a lone surrogate');
    }
    return value;
  });
}

function exceedsDepth(text, max) {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const character = text[i];
    if (inString) {
      if (character === '\\') {
        i++;
      } else if (character === '"') {
        inString = false;
      }
      continue;
    }

    if (character === '"') {
      inString = true;
    } else if (character === '{' || character === '[') {
      depth++;
      if (depth > max) {
        return true;
      }
    } else if (character === '}' || character === ']') {
      depth--;
    }
  }

  return false;
}

function isNonceInTimeWindow(nonce, now) {
  if (nonce.length < 13) {
    return false;
  }

  const unixMilli = Number('0x' + nonce.slice(0, 8) + nonce.slice(9, 13));
  if (Number.isNaN(unixMilli)) {
    return false;
  }

  const signedAt = Math.floor(unixMilli / 1000);

  if (now - signedAt > NONCE_MAX_AGE_SECONDS) {
    return false;
  }

  if (signedAt - now > CLOCK_SKEW_SECONDS) {
    return false;
  }

  return true;
}

function ed25519Verify(signature, publicKey, data) {
  try {
    const key = crypto.createPublicKey({ key: publicKey, format: 'raw-public', asymmetricKeyType: 'ed25519' });
    return crypto.verify(null, data, key, signature);
  } catch {
    return false;
  }
}

function decodeFromBase64(value, size) {
  if (typeof value !== 'string') {
    return undefined;
  }

  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    return undefined;
  }

  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== size) {
    return undefined;
  }

  return bytes;
}

function parseInteger(value) {
  if (typeof value !== 'string') {
    return undefined;
  }

  if (!/^-?\d+$/.test(value)) {
    return undefined;
  }

  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    return undefined;
  }

  return number;
}

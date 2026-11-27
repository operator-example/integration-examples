const KEY_LENGTH = 32;

export function loadConfig(env = process.env) {
  return {
    keyId: env.KEY_ID ?? '',
    operatorId: env.OPERATOR_ID ?? '',
    privateKey: env.PRIVATE_KEY ?? '',
    rootPublicKey: env.ROOT_PUBLIC_KEY ?? '',
    port: Number(env.PORT ?? 8080),
  };
}

export function getConfigErrors(config) {
  const errors = [];
  requireNonBlank(errors, 'KEY_ID', config.keyId);
  requireNonBlank(errors, 'OPERATOR_ID', config.operatorId);
  requireKey(errors, 'PRIVATE_KEY', config.privateKey);
  requireKey(errors, 'ROOT_PUBLIC_KEY', config.rootPublicKey);
  return errors;
}

function requireNonBlank(errors, name, value) {
  if (isBlank(value)) {
    errors.push(`${name} is not set`);
  }
}

function requireKey(errors, name, value) {
  if (isBlank(value)) {
    errors.push(`${name} is not set`);
    return;
  }

  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    errors.push(`${name} is not valid base64`);
    return;
  }

  const length = Buffer.from(value, 'base64').length;
  if (length !== KEY_LENGTH) {
    errors.push(`${name} must be a ${KEY_LENGTH}-byte raw Ed25519 key, got ${length} bytes`);
  }
}

function isBlank(value) {
  return typeof value !== 'string' || value.trim() === '';
}

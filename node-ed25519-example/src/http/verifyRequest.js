export function verifyRequestFromHeaders(headers) {
  return {
    version: singleHeader(headers, 'x-sign-version'),
    domain: singleHeader(headers, 'x-sign-domain'),
    nonce: singleHeader(headers, 'x-sign-nonce'),
    payload: singleHeader(headers, 'x-sign-payload'),
    signature: singleHeader(headers, 'x-sign-signature'),
    intermediatePublicKey: singleHeader(headers, 'x-sign-intermediate-public-key'),
    intermediateSignature: singleHeader(headers, 'x-sign-intermediate-signature'),
    intermediateNotBefore: singleHeader(headers, 'x-sign-intermediate-not-before'),
    intermediateNotAfter: singleHeader(headers, 'x-sign-intermediate-not-after'),
  };
}

function singleHeader(headers, name) {
  const values = headers[name];
  return values?.length === 1 ? values[0] : undefined;
}

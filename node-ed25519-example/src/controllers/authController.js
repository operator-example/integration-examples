import express from 'express';
import { verifyRequestFromHeaders } from '../http/verifyRequest.js';

export const MAX_BODY_SIZE = 8 * 1024 * 1024;

export function createAuthController(authService) {
  const router = express.Router();
  const readRawBody = express.raw({ type: () => true, limit: MAX_BODY_SIZE });

  router.post('/sign', readRawBody, (request, response) => {
    const signed = authService.sign(request.body ?? Buffer.alloc(0));
    response.json({
      key_id: signed.keyId,
      operator_id: signed.operatorId,
      payload: signed.payload,
      signature: signed.signature,
    });
  });

  router.post('/verify', readRawBody, (request, response) => {
    const body = request.body ?? Buffer.alloc(0);
    if (!authService.verify(verifyRequestFromHeaders(request.headersDistinct), body)) {
      response.status(401).json({ verified: false });
      return;
    }

    response.json({ verified: true });
  });

  return router;
}

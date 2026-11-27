import express from 'express';
import { createAuthController } from './controllers/authController.js';

export function createApp(authService) {
  const app = express();
  app.use('/Auth', createAuthController(authService));
  app.use(errorHandler);
  return app;
}

export function errorHandler(error, request, response, next) {
  if (response.headersSent) return next(error);

  if (error.type === 'entity.too.large') {
    response.status(413).json({ error: 'body is too large' });
    return;
  }

  if (error.expose && error.status >= 400 && error.status < 500) {
    response.status(error.status).json({ error: error.message });
    return;
  }

  console.error(error);
  response.status(500).json({ error: 'internal server error' });
}

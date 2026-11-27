import http from 'node:http';
import { once } from 'node:events';
import { createApp } from '../src/app.js';

export async function startServer(authService) {
  const server = http.createServer({ maxHeaderSize: 8 * 1024 * 1024 }, createApp(authService));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server;
}

export function baseUrlOf(server) {
  return `http://127.0.0.1:${server.address().port}/Auth`;
}

export async function stopServer(server) {
  server.close();
  server.closeAllConnections();
  await once(server, 'close');
}

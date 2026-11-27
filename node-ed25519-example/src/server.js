import http from 'node:http';
import { createApp } from './app.js';
import { getConfigErrors, loadConfig } from './config/appConfig.js';
import { AuthService } from './services/authService.js';

const MAX_HEADER_SIZE = 8 * 1024 * 1024;

const config = loadConfig();
const configErrors = getConfigErrors(config);
if (configErrors.length > 0) {
  console.error(`Invalid configuration:\n${configErrors.map((error) => `  - ${error}`).join('\n')}`);
  process.exit(1);
}

const app = createApp(new AuthService(config));
const server = http.createServer({ maxHeaderSize: MAX_HEADER_SIZE }, app);
server.listen(config.port, () => {
  console.log(`node-ed25519-example listening on ${config.port}`);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.once(signal, () => {
    server.close(() => process.exit(0));
  });
}

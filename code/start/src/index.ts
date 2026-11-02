import 'dotenv/config';
import { createApp } from './app';
import { readConfig } from './config';
import { createLogger } from './logger';
async function main() {
  const config = readConfig();
  const logger = createLogger(config.logDir);
  const app = await createApp({ config, logger });
  const server = app.listen(config.port, () => logger.info('server.started', { port: config.port }));
  server.on('error', () => { logger.error('server.failed'); logger.end(); process.exitCode = 1; });
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => {
      logger.info('server.stopping', { signal });
      server.close(() => logger.end());
      setTimeout(() => process.exit(1), 10_000).unref();
    });
  }
}
main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : 'Startup failed.');
  process.exitCode = 1;
});

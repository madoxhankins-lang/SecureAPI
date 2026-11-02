import { mkdirSync } from 'node:fs';
import winston from 'winston';

export function createLogger(logDir: string): winston.Logger {
  mkdirSync(logDir, { recursive: true });
  return winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [
      new winston.transports.Console(),
      new winston.transports.File({ filename: `${logDir}/combined.log`, maxsize: 5_000_000, maxFiles: 3 }),
      new winston.transports.File({ filename: `${logDir}/error.log`, level: 'error', maxsize: 5_000_000, maxFiles: 3 })
    ]
  });
}

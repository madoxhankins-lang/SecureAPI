const { randomBytes } = require('node:crypto');
const { writeFileSync, readFileSync, existsSync } = require('node:fs');
const path = require('node:path');
try {
  writeFileSync('.env', [
    'PORT=3000', `JWT_SECRET=${randomBytes(48).toString('hex')}`, 'JWT_TTL_SECONDS=900',
    'ADMIN_EMAIL=admin@example.com', `ADMIN_PASSWORD=${randomBytes(24).toString('base64url')}`,
    'CORS_ORIGINS=http://localhost:5173', 'LOG_DIR=logs', ''
  ].join('\n'), { flag: 'wx', mode: 0o600 });
  console.log('Created .env with random local credentials. Keep this file private.');
} catch (error) {
  if (error.code !== 'EEXIST') throw error;
  console.log('.env already exists; existing configuration was preserved.');
}

const collectionDir = path.resolve(__dirname, '../../../bruno/Secure API');
if (existsSync(collectionDir)) {
  const env = require('dotenv').parse(readFileSync('.env'));
  writeFileSync(path.join(collectionDir, '.env'), [
    `ADMIN_EMAIL=${JSON.stringify(env.ADMIN_EMAIL || '')}`,
    `ADMIN_PASSWORD=${JSON.stringify(env.ADMIN_PASSWORD || '')}`, ''
  ].join('\n'), { mode: 0o600 });
  console.log('Connected the Bruno collection to the local admin credentials.');
}

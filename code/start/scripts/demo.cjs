require('dotenv').config({ quiet: true });
const { randomBytes } = require('node:crypto');
const { writeFileSync } = require('node:fs');
const assert = require('node:assert/strict');
const base = `http://localhost:${process.env.PORT || 3000}`;
const captures = [];
async function call(label, method, path, expected, body, token) {
  const response = await fetch(base + path, { method, headers: {
    ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {})
  }, ...(body ? { body: JSON.stringify(body) } : {}) });
  const json = await response.json();
  assert.equal(response.status, expected, `${label}: unexpected response`);
  const safe = structuredClone(json);
  if (safe.data?.accessToken) safe.data.accessToken = '[REDACTED: bearer token]';
  const capture = { label, request: `${method} ${path}`, status: response.status, body: safe };
  captures.push(capture); console.log(JSON.stringify(capture, null, 2));
  return json;
}
async function main() {
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) throw new Error('Run npm run setup and start the server first.');
  const user = { email: `demo-${randomBytes(4).toString('hex')}@example.com`, password: randomBytes(24).toString('base64url') };
  await call('Server is running', 'GET', '/health', 200);
  await call('Register an ordinary user', 'POST', '/auth/register', 201, user);
  const login = await call('Login issues a token', 'POST', '/auth/login', 200, user);
  await call('Authenticated profile', 'GET', '/me', 200, undefined, login.data.accessToken);
  await call('No token: authentication fails', 'GET', '/secure', 401);
  await call('USER token: authorization fails', 'GET', '/secure', 403, undefined, login.data.accessToken);
  const admin = await call('Configured administrator login', 'POST', '/auth/login', 200, { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD });
  await call('ADMIN token: access allowed', 'GET', '/secure', 200, undefined, admin.data.accessToken);
  await call('Invalid signup: validation fails', 'POST', '/auth/register', 400, { email: 'invalid', password: 'short' });
  await call('Client cannot grant ADMIN role', 'POST', '/auth/register', 400, { ...user, role: 'ADMIN' });
  if (process.env.DEMO_OUTPUT) writeFileSync(process.env.DEMO_OUTPUT, JSON.stringify(captures, null, 2) + '\n');
  console.log('Demo passed. Tokens and passwords were not printed. See logs/combined.log for matching request IDs.');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });

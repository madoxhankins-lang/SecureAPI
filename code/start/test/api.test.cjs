const { test, before } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Writable } = require('node:stream');
const winston = require('winston');
const { createApp } = require('../dist/app');
const { readConfig } = require('../dist/config');
const { UserStore } = require('../dist/users');
const { errorHandler } = require('../dist/errors');

const config = {
  port: 3000, jwtSecret: 'test-only-secret-with-more-than-32-bytes', jwtTtlSeconds: 900,
  corsOrigins: ['http://localhost:5173'], logDir: 'logs',
  admin: { email: 'admin@example.com', password: 'Test-admin-password-123' }
};
const entries = [];
const logger = winston.createLogger({ format: winston.format.json(), transports: [new winston.transports.Stream({
  stream: new Writable({ write(chunk, _encoding, callback) { entries.push(JSON.parse(chunk.toString())); callback(); } })
})] });
let app, userToken, adminToken, userId;
const user = { email: 'student@example.com', password: 'Student-password-123' };
const bearer = token => ({ Authorization: `Bearer ${token}` });
const error = (response, status, code) => {
  assert.equal(response.status, status); assert.equal(response.body.error.code, code);
  assert.equal(response.body.requestId, response.headers['x-request-id']);
  assert.match(response.body.requestId, /^[0-9a-f-]{36}$/);
};
before(async () => {
  app = await createApp({ config, logger, apiLimit: 500, authLimit: 100 });
  const registered = await request(app).post('/auth/register').send(user).expect(201);
  userId = registered.body.data.user.id;
  userToken = (await request(app).post('/auth/login').send(user).expect(200)).body.data.accessToken;
  adminToken = (await request(app).post('/auth/login').send(config.admin).expect(200)).body.data.accessToken;
});
test('health and security headers', async () => {
  const r = await request(app).get('/health').expect(200);
  assert.equal(r.body.data.status, 'ok'); assert.equal(r.headers['x-content-type-options'], 'nosniff');
  assert.ok(r.headers['content-security-policy']); assert.equal(r.headers['x-powered-by'], undefined);
});
test('login returns a signed, expiring token and never returns credentials', async () => {
  const r = await request(app).post('/auth/login').send(user).expect(200);
  const p = jwt.verify(r.body.data.accessToken, config.jwtSecret, { algorithms: ['HS256'], issuer: 'secure-api', audience: 'secure-api-client' });
  assert.equal(p.exp - p.iat, 900); assert.equal(p.sub, userId); assert.equal(p.role, 'USER');
  assert.equal(r.headers['cache-control'], 'no-store');
  assert.ok(!JSON.stringify(r.body).includes('password'));
});
test('ordinary user can access /me', async () => {
  const r = await request(app).get('/me').set(bearer(userToken)).expect(200);
  assert.equal(r.body.data.user.email, user.email); assert.equal(r.body.data.user.role, 'USER');
});
test('no token is 401', async () => error(await request(app).get('/secure'), 401, 'AUTH_REQUIRED'));
test('ordinary user is 403 on /secure', async () => error(await request(app).get('/secure').set(bearer(userToken)), 403, 'FORBIDDEN'));
test('administrator is allowed on /secure', async () => {
  const r = await request(app).get('/secure').set(bearer(adminToken)).expect(200);
  assert.match(r.body.data.message, /administrator/);
});
test('malformed and tampered tokens are 401', async () => {
  for (const token of ['not-a-jwt', userToken.slice(0, -8) + 'tampered']) error(await request(app).get('/me').set(bearer(token)), 401, 'INVALID_TOKEN');
});
for (const [name, payload, options, secret] of [
  ['expired', {}, { expiresIn: -1 }],
  ['wrong audience', {}, { audience: 'someone-else' }],
  ['wrong issuer', {}, { issuer: 'someone-else' }],
  ['wrong algorithm', {}, { algorithm: 'HS384' }],
  ['missing expiry', {}, { expiresIn: undefined }],
  ['unknown account', {}, { subject: 'missing-user' }],
  ['wrong signing key', {}, {}, 'a-different-test-signing-key-123456789']
]) test(`${name} is rejected`, async () => {
  const opts = { algorithm: 'HS256', subject: userId, issuer: 'secure-api', audience: 'secure-api-client', expiresIn: 900, ...options };
  if (opts.expiresIn === undefined) delete opts.expiresIn;
  const token = jwt.sign(payload, secret || config.jwtSecret, opts);
  error(await request(app).get('/me').set(bearer(token)), 401, 'INVALID_TOKEN');
});
test('role in JWT cannot override the server role', async () => {
  const token = jwt.sign({ role: 'ADMIN' }, config.jwtSecret, { subject: userId, issuer: 'secure-api', audience: 'secure-api-client', expiresIn: 60 });
  error(await request(app).get('/secure').set(bearer(token)), 403, 'FORBIDDEN');
});
test('signup cannot request an admin role or extra fields', async () => {
  error(await request(app).post('/auth/register').send({ ...user, email: 'attacker@example.com', role: 'ADMIN' }), 400, 'VALIDATION_ERROR');
});
test('validation rejects missing, malformed and oversized credentials', async () => {
  for (const body of [{}, { email: 'invalid', password: 'short' }, { email: [], password: {} },
    { ...user, password: 'a'.repeat(73) }, { ...user, password: '😀'.repeat(19) }]) {
    const r = await request(app).post('/auth/register').send(body);
    error(r, 400, 'VALIDATION_ERROR'); assert.ok(r.body.error.details.length);
    assert.ok(!JSON.stringify(r.body).includes('😀'));
  }
});
test('email casing is normalized and duplicate email is rejected', async () => {
  error(await request(app).post('/auth/register').send({ ...user, email: 'STUDENT@example.com' }), 409, 'EMAIL_IN_USE');
  await request(app).post('/auth/login').send({ ...user, email: ' STUDENT@example.com ' }).expect(200);
});
test('wrong passwords and unknown emails share one error', async () => {
  for (const body of [{ ...user, password: 'wrong' }, { ...user, email: 'unknown@example.com' }]) {
    error(await request(app).post('/auth/login').send(body), 401, 'INVALID_CREDENTIALS');
  }
});
test('malformed JSON, large bodies, unknown paths and content types have consistent errors', async () => {
  error(await request(app).post('/auth/login').set('Content-Type', 'application/json').send('{broken'), 400, 'INVALID_JSON');
  error(await request(app).post('/auth/login').send({ value: 'x'.repeat(11000) }), 413, 'PAYLOAD_TOO_LARGE');
  error(await request(app).get('/missing'), 404, 'NOT_FOUND');
  error(await request(app).post('/auth/login').type('form').send('email=test'), 415, 'UNSUPPORTED_MEDIA_TYPE');
});
test('CORS allows configured browser origins and denies others', async () => {
  const allowed = await request(app).get('/health').set('Origin', 'http://localhost:5173').expect(200);
  assert.equal(allowed.headers['access-control-allow-origin'], 'http://localhost:5173');
  error(await request(app).get('/health').set('Origin', 'https://untrusted.example'), 403, 'ORIGIN_DENIED');
  await request(app).options('/auth/login').set('Origin', 'http://localhost:5173').set('Access-Control-Request-Method', 'POST').expect(204);
});
test('API rate limit returns 429, retry metadata and the same error envelope', async () => {
  const limited = await createApp({ config: { ...config, admin: undefined }, logger, apiLimit: 1 });
  await request(limited).get('/health').expect(200);
  const r = await request(limited).get('/health'); error(r, 429, 'RATE_LIMITED'); assert.ok(r.headers['retry-after']);
});
test('auth endpoints have a separate stricter limiter', async () => {
  const limited = await createApp({ config: { ...config, admin: undefined }, logger, authLimit: 1 });
  await request(limited).post('/auth/login').send(user).expect(401);
  error(await request(limited).post('/auth/login').send(user), 429, 'RATE_LIMITED');
  await request(limited).get('/health').expect(200);
});
test('successful registration and login do not consume the failed-auth allowance', async () => {
  const limited = await createApp({ config: { ...config, admin: undefined }, logger, authLimit: 1 });
  await request(limited).post('/auth/register').send(user).expect(201);
  await request(limited).post('/auth/login').send(user).expect(200);
  await request(limited).post('/auth/login').send(user).expect(200);
  await request(limited).post('/auth/login').send({ ...user, password: 'wrong' }).expect(401);
  error(await request(limited).post('/auth/login').send(user), 429, 'RATE_LIMITED');
});
test('passwords are hashed and concurrent registration cannot replace an account', async () => {
  const store = new UserStore();
  const results = await Promise.allSettled([store.add(user.email, user.password), store.add(user.email, 'another-password-123')]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const stored = store.byEmail(user.email); assert.notEqual(stored.passwordHash, user.password);
  assert.equal(bcrypt.getRounds(stored.passwordHash), 12);
});
test('unexpected exceptions are logged without exposing internals', () => {
  let status, body;
  const res = { locals: { requestId: 'test-id' }, status(s) { status = s; return this; }, json(b) { body = b; } };
  errorHandler(logger)(new Error('private-secret-stack'), { method: 'GET' }, res, () => assert.fail());
  assert.equal(status, 500); assert.equal(body.error.code, 'INTERNAL_ERROR');
  assert.ok(!JSON.stringify(body).includes('private-secret'));
});
test('logs correlate requests and never include passwords, tokens, query or path secrets', async () => {
  const r = await request(app).get('/health?password=private-query-secret').set('Authorization', 'Bearer private-header-secret');
  await request(app).get('/private-path-secret');
  const serialized = JSON.stringify(entries);
  for (const secret of [user.password, config.admin.password, userToken, adminToken, 'private-query-secret', 'private-header-secret', 'private-path-secret', 'private-secret-stack']) assert.ok(!serialized.includes(secret));
  assert.ok(entries.some(e => e.message === 'http.request' && e.requestId === r.body.requestId && e.status === 200));
  assert.ok(entries.some(e => e.message === 'request.error' && e.code === 'FORBIDDEN'));
});
test('configuration rejects missing secrets, partial admin config and invalid values', () => {
  for (const env of [{}, { JWT_SECRET: 'short' }, { JWT_SECRET: config.jwtSecret, ADMIN_EMAIL: 'admin@example.com' },
    { JWT_SECRET: config.jwtSecret, PORT: '0' }, { JWT_SECRET: config.jwtSecret, CORS_ORIGINS: '*' },
    { JWT_SECRET: config.jwtSecret, JWT_TTL_SECONDS: '999999' }]) assert.throws(() => readConfig(env));
  assert.equal(readConfig({ JWT_SECRET: config.jwtSecret }).port, 3000);
  assert.equal(readConfig({ JWT_SECRET: config.jwtSecret }).authRateLimit, 10);
  assert.equal(readConfig({ JWT_SECRET: config.jwtSecret, AUTH_RATE_LIMIT: '100' }).authRateLimit, 100);
  assert.throws(() => readConfig({ JWT_SECRET: config.jwtSecret, AUTH_RATE_LIMIT: '0' }));
});

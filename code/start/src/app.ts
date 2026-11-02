import express from 'express';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { randomUUID } from 'node:crypto';
import { body, checkExact } from 'express-validator';
import { rateLimit } from 'express-rate-limit';
import type { Logger } from 'winston';
import type { Config } from './config';
import { ApiError, errorHandler, validate } from './errors';
import { UserStore, publicUser, type User } from './users';
import { authenticate, issueToken, requireRole } from './auth';
interface Options { config: Config; logger: Logger; apiLimit?: number; authLimit?: number }
export async function createApp({ config, logger, apiLimit = 100, authLimit = config.authRateLimit ?? 10 }: Options) {
  const app = express();
  const users = new UserStore();
  if (config.admin) await users.add(config.admin.email, config.admin.password, 'ADMIN');
  const dummyHash = await bcrypt.hash(randomUUID(), 12);
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.locals.requestId = randomUUID();
    res.setHeader('X-Request-ID', res.locals.requestId);
    next();
  });
  app.use(morgan((tokens, req, res) => JSON.stringify({
    requestId: (res as express.Response).locals.requestId, method: tokens.method(req, res),
    // Route templates avoid leaking user-controlled paths or query strings into logs.
    route: (req as express.Request).route?.path ?? 'unmatched',
    status: Number(tokens.status(req, res)), durationMs: Number(tokens['response-time'](req, res))
  }), { stream: { write: line => logger.info('http.request', JSON.parse(line)) } }));
  app.use(helmet());
  const limiter = (limit: number, windowMs: number, skipSuccessfulRequests = false) => rateLimit({
    windowMs, limit, standardHeaders: 'draft-8', legacyHeaders: false,
    skipSuccessfulRequests,
    handler: (_req, res, next) => next(new ApiError(429, 'RATE_LIMITED', `Too many requests. Try again in ${res.getHeader('Retry-After')} seconds.`))
  });
  app.use(limiter(apiLimit, 60_000));
  app.use(cors({
    origin: (origin, callback) => {
      if (!origin || config.corsOrigins.includes(origin)) callback(null, true);
      else callback(new ApiError(403, 'ORIGIN_DENIED', 'This browser origin is not allowed.'));
    },
    methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'], exposedHeaders: ['X-Request-ID']
  }));
  app.use('/auth', limiter(authLimit, 15 * 60_000, true));
  app.use(express.json({ limit: '10kb', strict: true }));
  app.use((req, _res, next) => {
    if (req.method === 'POST' && !req.is('application/json')) throw new ApiError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Send the request as application/json.');
    next();
  });
  const credentials = (register: boolean) => [
    body('email').isString().bail().trim().isLength({ max: 254 }).isEmail().withMessage('Use a valid email address.').bail().toLowerCase(),
    body('password').isString().withMessage('Password must be a string.').bail()
      .custom((value: string) => value.length >= (register ? 12 : 1) && Buffer.byteLength(value, 'utf8') <= 72)
      .withMessage(register ? 'Use at least 12 characters and at most 72 UTF-8 bytes.' : 'Invalid password length.'),
    checkExact([], { locations: ['body'], message: 'Only email and password are allowed.' }), validate
  ];
  app.get('/health', (_req, res) => { res.json({ data: { status: 'ok' }, requestId: res.locals.requestId }); });
  app.post('/auth/register', ...credentials(true), async (req, res) => {
    const user = await users.add(req.body.email, req.body.password);
    res.status(201).json({ data: { user: publicUser(user) }, requestId: res.locals.requestId });
  });
  app.post('/auth/login', ...credentials(false), async (req, res) => {
    const user = users.byEmail(req.body.email);
    const valid = await bcrypt.compare(req.body.password, user?.passwordHash ?? dummyHash);
    if (!user || !valid) throw new ApiError(401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
    res.setHeader('Cache-Control', 'no-store');
    res.json({ data: { accessToken: issueToken(user, config), tokenType: 'Bearer', expiresIn: config.jwtTtlSeconds,
      user: publicUser(user) }, requestId: res.locals.requestId });
  });
  const auth = authenticate(config, users);
  app.get('/me', auth, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({ data: { user: publicUser(res.locals.user as User) }, requestId: res.locals.requestId });
  });
  app.get('/secure', auth, requireRole('ADMIN'), (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({ data: { message: 'Welcome, administrator. You have access to the secure endpoint.' }, requestId: res.locals.requestId });
  });
  app.use((_req, _res, next) => next(new ApiError(404, 'NOT_FOUND', 'The requested endpoint does not exist.')));
  app.use(errorHandler(logger));
  return app;
}

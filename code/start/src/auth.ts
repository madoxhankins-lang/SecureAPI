import jwt from 'jsonwebtoken';
import type { RequestHandler } from 'express';
import type { Config } from './config';
import { ApiError } from './errors';
import { UserStore, type Role, type User } from './users';
const issuer = 'secure-api';
const audience = 'secure-api-client';
export function issueToken(user: User, config: Config): string {
  return jwt.sign({ role: user.role }, config.jwtSecret, {
    algorithm: 'HS256', subject: user.id, issuer, audience, expiresIn: config.jwtTtlSeconds
  });
}
export function authenticate(config: Config, users: UserStore): RequestHandler {
  return (req, res, next) => {
    const match = /^Bearer ([^\s]+)$/i.exec(req.get('authorization') ?? '');
    if (!match) throw new ApiError(401, 'AUTH_REQUIRED', 'A Bearer access token is required.');
    try {
      const payload = jwt.verify(match[1], config.jwtSecret, { algorithms: ['HS256'], issuer, audience });
      if (typeof payload === 'string' || typeof payload.sub !== 'string' || typeof payload.exp !== 'number') throw new Error('Invalid claims');
      const user = users.byId(payload.sub);
      if (!user) throw new Error('Unknown account');
      // Trust the server's user record for authorization, never client-supplied roles.
      res.locals.user = user;
    } catch { throw new ApiError(401, 'INVALID_TOKEN', 'The access token is invalid or expired.'); }
    next();
  };
}
export function requireRole(role: Role): RequestHandler {
  return (_req, res, next) => {
    if ((res.locals.user as User | undefined)?.role !== role) throw new ApiError(403, 'FORBIDDEN', 'This endpoint requires the ADMIN role.');
    next();
  };
}

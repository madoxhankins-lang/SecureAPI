export interface Config {
  port: number;
  jwtSecret: string;
  jwtTtlSeconds: number;
  authRateLimit?: number;
  corsOrigins: string[];
  logDir: string;
  admin?: { email: string; password: string };
}

export function readConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const secret = env.JWT_SECRET ?? '';
  if (Buffer.byteLength(secret) < 32 || /replace|change.?me/i.test(secret)) {
    throw new Error('JWT_SECRET must contain at least 32 bytes and must not be a placeholder.');
  }
  function integer(value: string | undefined, fallback: number, max: number): number {
    const parsed = value === undefined ? fallback : Number(value);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > max) throw new Error('Invalid numeric configuration.');
    return parsed;
  }
  const email = env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = env.ADMIN_PASSWORD;
  if (Boolean(email) !== Boolean(password)) throw new Error('Set both ADMIN_EMAIL and ADMIN_PASSWORD, or neither.');
  if (email && (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password || password.length < 12 || Buffer.byteLength(password) > 72 || /replace|change.?me/i.test(password))) {
    throw new Error('Admin credentials require a valid email and a non-placeholder password of 12 characters to 72 UTF-8 bytes.');
  }
  const corsOrigins = (env.CORS_ORIGINS ?? '').split(',').map(s => s.trim()).filter(Boolean);
  if (corsOrigins.some(origin => { try { return new URL(origin).origin !== origin; } catch { return true; } })) {
    throw new Error('CORS_ORIGINS must contain comma-separated origins, without paths or wildcards.');
  }
  return {
    port: integer(env.PORT, 3000, 65535), jwtSecret: secret,
    jwtTtlSeconds: integer(env.JWT_TTL_SECONDS, 900, 3600),
    authRateLimit: integer(env.AUTH_RATE_LIMIT, 10, 1000),
    corsOrigins, logDir: env.LOG_DIR || 'logs',
    ...(email && password ? { admin: { email, password } } : {})
  };
}

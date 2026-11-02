import type { ErrorRequestHandler, RequestHandler } from 'express';
import type { Logger } from 'winston';
import { validationResult } from 'express-validator';

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public details?: { field: string; message: string }[]) { super(message); }
}
export const validate: RequestHandler = (req, _res, next) => {
  const result = validationResult(req);
  if (!result.isEmpty()) throw new ApiError(400, 'VALIDATION_ERROR', 'Request validation failed.', result.array().map(error => ({
    field: error.type === 'field' ? error.path : 'body', message: String(error.msg)
  })));
  next();
};
export function errorHandler(logger: Logger): ErrorRequestHandler {
  return (err: unknown, req, res, next) => {
    if (res.headersSent) { next(err); return; }
    const type = (err as { type?: string } | null)?.type;
    const error = err instanceof ApiError ? err : type === 'entity.parse.failed'
      ? new ApiError(400, 'INVALID_JSON', 'Request body must be valid JSON.')
      : type === 'entity.too.large'
        ? new ApiError(413, 'PAYLOAD_TOO_LARGE', 'Request body exceeds 10 KB.')
        : new ApiError(500, 'INTERNAL_ERROR', 'An unexpected error occurred.');
    // Never serialize arbitrary errors, headers, query strings, or request bodies.
    logger.log(error.status >= 500 ? 'error' : 'warn', 'request.error', {
      requestId: res.locals.requestId, method: req.method, status: error.status, code: error.code
    });
    res.status(error.status).json({ error: { code: error.code, message: error.message,
      ...(error.details ? { details: error.details } : {}) }, requestId: res.locals.requestId });
  };
}

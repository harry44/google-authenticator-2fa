import { getSession } from './store.js';

/** Bearer-token guard for routes that need a logged-in user. */
export function requireAuth(req, res, next) {
  const [scheme, token] = String(req.headers.authorization || '').split(' ');
  const session = scheme === 'Bearer' && token ? getSession(token) : null;

  if (!session) {
    return res.status(401).json({ error: 'UNAUTHORIZED', message: 'A valid session token is required.' });
  }

  req.user = session.user;
  req.sessionToken = session.token;
  return next();
}

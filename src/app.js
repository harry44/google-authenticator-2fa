import express from 'express';
import bcrypt from 'bcryptjs';
import { config } from './config.js';
import {
  createChallenge,
  createSession,
  createUser,
  deleteChallenge,
  deleteSession,
  findUserByEmail,
  findUserById,
  getChallenge,
  publicUser,
  recordChallengeFailure,
  updateUser,
} from './store.js';
import { buildOtpAuthUrl, createTotpSecret, makeQrDataUrl, verifyTotp } from './totp.js';
import { consumeBackupCode, generateBackupCodes, hashBackupCodes } from './backup-codes.js';
import { requireAuth } from './auth.js';

export const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));

// Express 4 does not catch rejected promises in handlers.
const wrap = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function fail(res, status, error, message) {
  return res.status(status).json({ error, message });
}

app.get('/', (req, res) => {
  res.json({
    name: 'google-authenticator-2fa',
    endpoints: [
      'POST /api/register',
      'POST /api/login',
      'GET  /api/me',
      'POST /api/logout',
      'POST /api/2fa/setup',
      'POST /api/2fa/enable',
      'POST /api/2fa/verify',
      'POST /api/2fa/disable',
    ],
  });
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/api/register', wrap(async (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');

  if (!EMAIL_RE.test(email)) {
    return fail(res, 400, 'INVALID_EMAIL', 'Enter a valid email address.');
  }
  if (password.length < 8 || Buffer.byteLength(password) > 72) {
    return fail(res, 400, 'INVALID_PASSWORD', 'Use a password of 8-72 characters.');
  }
  if (findUserByEmail(email)) {
    return fail(res, 409, 'EMAIL_TAKEN', 'That email is already registered.');
  }

  const passwordHash = await bcrypt.hash(password, config.bcryptRounds);
  const user = createUser({ email, passwordHash });
  return res.status(201).json({ id: user.id, email: user.email });
}));

app.post('/api/login', wrap(async (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');
  const user = findUserByEmail(email);
  const passwordOk = user ? await bcrypt.compare(password, user.passwordHash) : false;

  if (!passwordOk) {
    return fail(res, 401, 'INVALID_CREDENTIALS', 'Email or password is incorrect.');
  }

  if (user.totpEnabled) {
    const challenge = createChallenge(user.id);
    return res.json({
      requires2fa: true,
      challengeId: challenge.id,
      expiresAt: new Date(challenge.expiresAt).toISOString(),
    });
  }

  const session = createSession(user.id);
  return res.json({ token: session.token, user: publicUser(user) });
}));

app.get('/api/me', requireAuth, (req, res) => res.json(publicUser(req.user)));

app.post('/api/logout', requireAuth, (req, res) => {
  deleteSession(req.sessionToken);
  res.json({ ok: true });
});

app.post('/api/2fa/setup', requireAuth, wrap(async (req, res) => {
  const user = findUserById(req.user.id);
  if (user.totpEnabled) {
    return fail(res, 409, 'ALREADY_ENABLED', '2FA is already enabled for this account.');
  }

  // Reuse the pending secret so refreshing the setup screen does not
  // invalidate a QR code the user has already scanned.
  const secret = user.pendingTotpSecret || createTotpSecret();
  if (!user.pendingTotpSecret) {
    updateUser(user.id, { pendingTotpSecret: secret });
  }

  const otpauthUrl = buildOtpAuthUrl({ secret, accountName: user.email });
  const qrDataUrl = await makeQrDataUrl(otpauthUrl);
  return res.json({ secret, otpauthUrl, qrDataUrl });
}));

app.post('/api/2fa/enable', requireAuth, wrap(async (req, res) => {
  const user = findUserById(req.user.id);
  if (user.totpEnabled) {
    return fail(res, 409, 'ALREADY_ENABLED', '2FA is already enabled for this account.');
  }
  if (!user.pendingTotpSecret) {
    return fail(res, 409, 'NO_PENDING_SECRET', 'Call /api/2fa/setup before enabling 2FA.');
  }

  const result = await verifyTotp(user.pendingTotpSecret, req.body?.token);
  if (!result.valid) {
    return fail(res, 401, 'INVALID_CODE', 'That code is not valid. Try the current code from the app.');
  }

  const backupCodes = generateBackupCodes();
  const backupCodeHashes = await hashBackupCodes(backupCodes);

  updateUser(user.id, {
    totpSecret: user.pendingTotpSecret,
    pendingTotpSecret: null,
    totpEnabled: true,
    backupCodeHashes,
    lastTotpStep: result.timeStep,
  });

  return res.json({ enabled: true, backupCodes });
}));

app.post('/api/2fa/verify', wrap(async (req, res) => {
  const challengeId = String(req.body?.challengeId ?? '');
  const challenge = getChallenge(challengeId);
  if (!challenge) {
    return fail(res, 401, 'CHALLENGE_EXPIRED', 'Login challenge expired. Sign in again.');
  }

  const user = findUserById(challenge.userId);
  if (!user?.totpEnabled) {
    return fail(res, 409, 'NOT_ENABLED', '2FA is not enabled for this account.');
  }

  const totp = await verifyTotp(user.totpSecret, req.body?.token, user.lastTotpStep);
  if (totp.valid) {
    deleteChallenge(challengeId);
    updateUser(user.id, { lastTotpStep: totp.timeStep });
    const session = createSession(user.id);
    return res.json({ token: session.token, usedBackupCode: false, user: publicUser(user) });
  }

  const backup = await consumeBackupCode(user.backupCodeHashes, req.body?.token);
  if (backup.valid) {
    deleteChallenge(challengeId);
    updateUser(user.id, { backupCodeHashes: backup.remaining });
    const session = createSession(user.id);
    return res.json({
      token: session.token,
      usedBackupCode: true,
      remainingBackupCodes: backup.remaining.length,
      user: publicUser(findUserById(user.id)),
    });
  }

  if (recordChallengeFailure(challengeId)) {
    return fail(res, 429, 'TOO_MANY_ATTEMPTS', 'Too many invalid codes. Sign in again.');
  }
  return fail(res, 401, 'INVALID_CODE', 'That code is not valid.');
}));

app.post('/api/2fa/disable', requireAuth, wrap(async (req, res) => {
  const user = findUserById(req.user.id);
  if (!user.totpEnabled) {
    return fail(res, 409, 'NOT_ENABLED', '2FA is not enabled for this account.');
  }

  const password = String(req.body?.password ?? '');
  if (!(await bcrypt.compare(password, user.passwordHash))) {
    return fail(res, 401, 'INVALID_CREDENTIALS', 'Password is incorrect.');
  }

  const totp = await verifyTotp(user.totpSecret, req.body?.token, user.lastTotpStep);
  let valid = totp.valid;
  let remaining = user.backupCodeHashes;
  if (!valid) {
    const backup = await consumeBackupCode(user.backupCodeHashes, req.body?.token);
    valid = backup.valid;
    remaining = backup.remaining;
  }
  if (!valid) {
    return fail(res, 401, 'INVALID_CODE', 'Enter a current authenticator code or a backup code.');
  }

  updateUser(user.id, {
    totpEnabled: false,
    totpSecret: null,
    pendingTotpSecret: null,
    backupCodeHashes: [],
    lastTotpStep: null,
  });
  return res.json({ enabled: false });
}));

app.use((req, res) => fail(res, 404, 'NOT_FOUND', 'Unknown endpoint.'));

app.use((err, req, res, next) => {
  if (err?.type === 'entity.parse.failed') {
    return fail(res, 400, 'INVALID_JSON', 'Request body must be valid JSON.');
  }
  console.error(err);
  return fail(res, 500, 'INTERNAL', 'Something went wrong.');
});

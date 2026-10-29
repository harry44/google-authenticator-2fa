import { randomBytes, randomUUID } from 'node:crypto';
import { config } from './config.js';

const users = new Map();
const usersByEmail = new Map();
const sessions = new Map();
const challenges = new Map();

export function resetStore() {
  users.clear();
  usersByEmail.clear();
  sessions.clear();
  challenges.clear();
}

export function createUser({ email, passwordHash }) {
  const normalizedEmail = String(email).trim().toLowerCase();
  const user = {
    id: randomUUID(),
    email: normalizedEmail,
    passwordHash,
    // Secret shown during setup, promoted to totpSecret only after a valid code.
    pendingTotpSecret: null,
    totpSecret: null,
    totpEnabled: false,
    backupCodeHashes: [],
    // Last accepted TOTP time step, used to reject replayed codes.
    lastTotpStep: null,
    createdAt: new Date().toISOString(),
  };
  users.set(user.id, user);
  usersByEmail.set(normalizedEmail, user);
  return user;
}

export function findUserByEmail(email) {
  return usersByEmail.get(String(email || '').trim().toLowerCase()) || null;
}

export function findUserById(id) {
  return users.get(id) || null;
}

export function updateUser(id, patch) {
  const user = users.get(id);
  if (!user) {
    return null;
  }
  Object.assign(user, patch);
  return user;
}

/** Everything safe to return over HTTP: no hashes, no TOTP secret. */
export function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    totpEnabled: user.totpEnabled,
    backupCodesRemaining: user.backupCodeHashes.length,
  };
}

export function createSession(userId, ttlMs = config.sessionTtlMs) {
  const token = randomBytes(32).toString('base64url');
  const session = { token, userId, expiresAt: Date.now() + ttlMs };
  sessions.set(token, session);
  return session;
}

export function getSession(token) {
  const session = sessions.get(token);
  if (!session) {
    return null;
  }
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  const user = findUserById(session.userId);
  return user ? { ...session, user } : null;
}

export function deleteSession(token) {
  sessions.delete(token);
}

export function createChallenge(userId, ttlMs = config.challengeTtlMs) {
  const challenge = {
    id: randomUUID(),
    userId,
    attempts: 0,
    expiresAt: Date.now() + ttlMs,
  };
  challenges.set(challenge.id, challenge);
  return challenge;
}

export function getChallenge(id) {
  const challenge = challenges.get(id);
  if (!challenge) {
    return null;
  }
  if (challenge.expiresAt <= Date.now()) {
    challenges.delete(id);
    return null;
  }
  return challenge;
}

export function deleteChallenge(id) {
  challenges.delete(id);
}

/** Returns true when the challenge has just been exhausted. */
export function recordChallengeFailure(id) {
  const challenge = challenges.get(id);
  if (!challenge) {
    return true;
  }
  challenge.attempts += 1;
  if (challenge.attempts >= config.challengeMaxAttempts) {
    challenges.delete(id);
    return true;
  }
  return false;
}

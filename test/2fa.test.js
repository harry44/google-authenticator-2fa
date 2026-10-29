import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { generate } from 'otplib';
import { app } from '../src/app.js';
import { config } from '../src/config.js';
import { freezeClock } from '../src/clock.js';
import { resetStore } from '../src/store.js';

// Keep bcrypt fast in tests; production uses 12 rounds.
config.bcryptRounds = 4;

const EPOCH = 1_800_000_000; // exact multiple of the 30-second TOTP period
const PASSWORD = 'correct-horse-battery';
const EMAIL = 'ada@example.com';

beforeEach(() => {
  resetStore();
  freezeClock(EPOCH);
});

async function register(email = EMAIL, password = PASSWORD) {
  const res = await request(app).post('/api/register').send({ email, password });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return res.body;
}

function login(email = EMAIL, password = PASSWORD) {
  return request(app).post('/api/login').send({ email, password });
}

async function enable2fa() {
  await register();
  const loginRes = await login();
  assert.equal(loginRes.status, 200);

  const setup = await request(app)
    .post('/api/2fa/setup')
    .set('Authorization', `Bearer ${loginRes.body.token}`);
  assert.equal(setup.status, 200, JSON.stringify(setup.body));

  const code = await generate({ secret: setup.body.secret, epoch: EPOCH });
  const enable = await request(app)
    .post('/api/2fa/enable')
    .set('Authorization', `Bearer ${loginRes.body.token}`)
    .send({ token: code });
  assert.equal(enable.status, 200, JSON.stringify(enable.body));

  return {
    token: loginRes.body.token,
    secret: setup.body.secret,
    backupCodes: enable.body.backupCodes,
  };
}

test('register validates email and password', async () => {
  let res = await request(app).post('/api/register').send({ email: 'not-an-email', password: PASSWORD });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'INVALID_EMAIL');

  res = await request(app).post('/api/register').send({ email: EMAIL, password: 'short' });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'INVALID_PASSWORD');
});

test('register rejects a duplicate email', async () => {
  await register();
  const res = await request(app).post('/api/register').send({ email: EMAIL, password: PASSWORD });
  assert.equal(res.status, 409);
  assert.equal(res.body.error, 'EMAIL_TAKEN');
});

test('login returns a session when 2FA is off', async () => {
  await register();
  const res = await login();
  assert.equal(res.status, 200);
  assert.ok(res.body.token);

  const me = await request(app).get('/api/me').set('Authorization', `Bearer ${res.body.token}`);
  assert.equal(me.status, 200);
  assert.equal(me.body.email, EMAIL);
  assert.equal(me.body.totpEnabled, false);
  assert.equal(me.body.passwordHash, undefined);
  assert.equal(me.body.totpSecret, undefined);

  const bad = await login(EMAIL, 'wrong-password');
  assert.equal(bad.status, 401);
  assert.equal(bad.body.error, 'INVALID_CREDENTIALS');
});

test('setup returns a QR code and reuses the pending secret', async () => {
  await register();
  const loginRes = await login();
  const auth = { Authorization: `Bearer ${loginRes.body.token}` };

  const first = await request(app).post('/api/2fa/setup').set(auth);
  assert.equal(first.status, 200);
  assert.match(first.body.secret, /^[A-Z2-7]{32}$/);
  assert.match(first.body.otpauthUrl, /^otpauth:\/\/totp\//);
  assert.match(first.body.qrDataUrl, /^data:image\/png;base64,/);

  const second = await request(app).post('/api/2fa/setup').set(auth);
  assert.equal(second.body.secret, first.body.secret);
});

test('a valid TOTP enables 2FA and a replayed code is rejected', async () => {
  const { secret } = await enable2fa();

  const first = await login();
  assert.equal(first.status, 200);
  assert.equal(first.body.requires2fa, true);
  assert.ok(first.body.challengeId);

  freezeClock(EPOCH + 30);
  const code = await generate({ secret, epoch: EPOCH + 30 });
  const verified = await request(app)
    .post('/api/2fa/verify')
    .send({ challengeId: first.body.challengeId, token: code });
  assert.equal(verified.status, 200, JSON.stringify(verified.body));
  assert.equal(verified.body.usedBackupCode, false);
  assert.ok(verified.body.token);

  const me = await request(app).get('/api/me').set('Authorization', `Bearer ${verified.body.token}`);
  assert.equal(me.body.totpEnabled, true);

  const replayLogin = await login();
  const replay = await request(app)
    .post('/api/2fa/verify')
    .send({ challengeId: replayLogin.body.challengeId, token: code });
  assert.equal(replay.status, 401);
  assert.equal(replay.body.error, 'INVALID_CODE');
});

test('a backup code works once and is removed from the list', async () => {
  const { backupCodes } = await enable2fa();
  assert.equal(backupCodes.length, 10);

  const first = await login();
  const used = await request(app)
    .post('/api/2fa/verify')
    .send({ challengeId: first.body.challengeId, token: backupCodes[0] });
  assert.equal(used.status, 200, JSON.stringify(used.body));
  assert.equal(used.body.usedBackupCode, true);
  assert.equal(used.body.remainingBackupCodes, 9);

  const replayLogin = await login();
  const replay = await request(app)
    .post('/api/2fa/verify')
    .send({ challengeId: replayLogin.body.challengeId, token: backupCodes[0] });
  assert.equal(replay.status, 401);

  const secondLogin = await login();
  const next = await request(app)
    .post('/api/2fa/verify')
    .send({ challengeId: secondLogin.body.challengeId, token: backupCodes[1] });
  assert.equal(next.status, 200);
  assert.equal(next.body.remainingBackupCodes, 8);
});

test('disable requires the password and a valid code', async () => {
  const { secret, token } = await enable2fa();
  const auth = { Authorization: `Bearer ${token}` };

  const wrongPassword = await request(app)
    .post('/api/2fa/disable')
    .set(auth)
    .send({ password: 'nope-nope-nope', token: '000000' });
  assert.equal(wrongPassword.status, 401);

  freezeClock(EPOCH + 30);
  const code = await generate({ secret, epoch: EPOCH + 30 });
  const disabled = await request(app)
    .post('/api/2fa/disable')
    .set(auth)
    .send({ password: PASSWORD, token: code });
  assert.equal(disabled.status, 200, JSON.stringify(disabled.body));
  assert.equal(disabled.body.enabled, false);

  const after = await login();
  assert.equal(after.status, 200);
  assert.equal(after.body.requires2fa, undefined);
  assert.ok(after.body.token);
});

test('too many invalid codes exhaust the login challenge', async () => {
  await enable2fa();
  const loginRes = await login();
  const { challengeId } = loginRes.body;

  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const res = await request(app).post('/api/2fa/verify').send({ challengeId, token: 'ABCDEF' });
    assert.equal(res.status, attempt === 5 ? 429 : 401);
  }

  const after = await request(app).post('/api/2fa/verify').send({ challengeId, token: 'ABCDEF' });
  assert.equal(after.status, 401);
  assert.equal(after.body.error, 'CHALLENGE_EXPIRED');
});

test('protected routes reject missing or invalid tokens', async () => {
  let res = await request(app).get('/api/me');
  assert.equal(res.status, 401);

  res = await request(app).post('/api/2fa/setup').set('Authorization', 'Bearer not-a-token');
  assert.equal(res.status, 401);
});

test('enable rejects a malformed code', async () => {
  await register();
  const loginRes = await login();
  const setup = await request(app)
    .post('/api/2fa/setup')
    .set('Authorization', `Bearer ${loginRes.body.token}`);
  assert.equal(setup.status, 200);

  const res = await request(app)
    .post('/api/2fa/enable')
    .set('Authorization', `Bearer ${loginRes.body.token}`)
    .send({ token: 'ABC' });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'INVALID_CODE');
});

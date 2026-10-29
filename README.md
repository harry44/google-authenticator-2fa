# Google Authenticator 2FA with Node.js

A small, complete TOTP implementation: enroll a user, show a QR code that
Google Authenticator can scan, verify six-digit codes at login, and recover
with single-use backup codes.

No database is required for the demo — users live in memory — but every
security decision is written the way it should be in production.

```
register ──► setup (secret + QR) ──► scan ──► enable (verify code) ──► backup codes
                                                    │
login (password) ──► challenge ──► verify TOTP/backup code ──► session token
```

## Requirements

- Node.js 20 or newer (uses `node:test`, ESM and `crypto.randomUUID`)
- Google Authenticator, Authy, 1Password, Microsoft Authenticator or any
  TOTP-compatible app

## Run it

```bash
npm install
npm start
# Google Authenticator 2FA demo listening on http://localhost:3000
```

Run the tests:

```bash
npm test
```

Generate a code from a secret without a phone (handy while developing):

```bash
npm run code -- P3RUYUMVH4BFPLGRBXPHO2RAYY6JIZJA
```

## API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/register` | – | Create an account |
| `POST` | `/api/login` | – | Password step; returns a session or a 2FA challenge |
| `GET` | `/api/me` | Bearer | Current user |
| `POST` | `/api/logout` | Bearer | Revoke the session |
| `POST` | `/api/2fa/setup` | Bearer | Generate secret + `otpauth://` URI + QR data URL |
| `POST` | `/api/2fa/enable` | Bearer | Verify a code and return backup codes |
| `POST` | `/api/2fa/verify` | – | Complete login with a TOTP or backup code |
| `POST` | `/api/2fa/disable` | Bearer | Turn 2FA off with password + code |

### 1. Register and log in

```bash
curl -s -X POST localhost:3000/api/register \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse-battery"}'

TOKEN=$(curl -s -X POST localhost:3000/api/login \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse-battery"}' | jq -r .token)
```

### 2. Start enrollment

```bash
curl -s -X POST localhost:3000/api/2fa/setup \
  -H "authorization: Bearer $TOKEN" | jq
```

Response:

```json
{
  "secret": "P3RUYUMVH4BFPLGRBXPHO2RAYY6JIZJA",
  "otpauthUrl": "otpauth://totp/GroovyGrails%20Demo:ada%40example.com?secret=...&issuer=GroovyGrails%20Demo",
  "qrDataUrl": "data:image/png;base64,iVBORw0KGgo..."
}
```

Open the data URL in a browser and scan it with Google Authenticator, or enter
the `secret` manually. The secret is stored as `pendingTotpSecret` until a code
is verified, so an abandoned setup cannot lock the user out.

### 3. Enable and save backup codes

```bash
CODE=$(npm run --silent code -- P3RUYUMVH4BFPLGRBXPHO2RAYY6JIZJA)

curl -s -X POST localhost:3000/api/2fa/enable \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$CODE\"}" | jq
```

The response contains ten codes such as `K7M2P-9XQ4R`. They are returned in
plaintext **once**; only bcrypt hashes are stored. Every code is removed from
the list after it is used.

### 4. Log in with 2FA

```bash
CHALLENGE=$(curl -s -X POST localhost:3000/api/login \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse-battery"}' | jq -r .challengeId)

CODE=$(npm run --silent code -- P3RUYUMVH4BFPLGRBXPHO2RAYY6JIZJA)

curl -s -X POST localhost:3000/api/2fa/verify \
  -H 'content-type: application/json' \
  -d "{\"challengeId\":\"$CHALLENGE\",\"token\":\"$CODE\"}" | jq
```

A valid code returns a session token. Sending the same code again returns
`401 INVALID_CODE` because the accepted time step is recorded per user.

## How the code is organised

| File | Responsibility |
| --- | --- |
| `src/totp.js` | Secret generation, `otpauth://` URI, QR data URL, code verification |
| `src/backup-codes.js` | Code generation, bcrypt hashing, one-time consumption |
| `src/store.js` | In-memory users, sessions and login challenges |
| `src/auth.js` | Bearer-token middleware |
| `src/app.js` | HTTP routes and error handling |
| `src/clock.js` | Injectable clock so tests can control TOTP steps |

### Secret and QR code

```js
import { generateSecret, generateURI } from 'otplib';
import QRCode from 'qrcode';

const secret = generateSecret(); // 32 Base32 characters
const otpauthUrl = generateURI({
  secret,
  label: 'ada@example.com',
  issuer: 'GroovyGrails Demo',
});
const qrDataUrl = await QRCode.toDataURL(otpauthUrl, { width: 240 });
```

`otpauth://totp/Issuer:account?secret=...&issuer=Issuer` is the format
Google Authenticator reads. Defaults are SHA-1, six digits and a 30-second
period — change them only if the app you target supports it.

### Verify with replay protection

```js
import { verify } from 'otplib';

const result = await verify({
  secret,
  token: '123456',
  epoch: Math.floor(Date.now() / 1000),
  epochTolerance: 30,        // accept the previous/next step
  afterTimeStep: lastStep,   // reject codes at or before the last used step
});
// result.valid, result.timeStep
```

`epochTolerance` is measured in **seconds** in otplib 13, not time steps.
`afterTimeStep` is what stops a code observed over someone's shoulder from
being replayed for the rest of the 30-second window.

### Backup codes

```js
const codes = generateBackupCodes();          // K7M2P-9XQ4R, ...
const hashes = await hashBackupCodes(codes);   // bcrypt, 12 rounds each
const { valid, remaining } = await consumeBackupCode(hashes, input);
```

Normalise input first (`ABC-DE` → `ABCDE`), compare against every hash, and
delete the matching hash. A backup code that has been used must never work a
second time.

## Security checklist

- Treat the TOTP secret like a password. It is returned only to the
  authenticated owner during setup, never from `/api/me`.
- Store only bcrypt hashes of passwords and backup codes, never plaintext.
- Return backup codes exactly once and let the user download or print them.
- Require a current code (or backup code) **and** the password to disable 2FA.
- Reject replayed TOTP steps with `afterTimeStep`.
- Expire login challenges (5 minutes) and cap invalid attempts (5).
- Rate-limit `/api/login` and `/api/2fa/verify` at the edge (nginx) or with
  `express-rate-limit`; this demo leaves that to the deployment layer.
- Serve HTTPS in production. A TOTP code is useless over plain HTTP.
- Replace the in-memory store with a database and encrypt the TOTP secret at
  rest (for example with a KMS-backed key).
- Log 2FA enable/disable events and notify the account owner by email.

## Environment variables

Copy `.env.example` and load it with your process manager or `node --env-file`:

```bash
node --env-file=.env src/server.js
```

## License

MIT

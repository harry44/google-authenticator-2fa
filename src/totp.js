import QRCode from 'qrcode';
import { generate, generateSecret, generateURI, verify } from 'otplib';
import { config } from './config.js';
import { nowSeconds } from './clock.js';

/** Base32 secret, 20 random bytes, compatible with every authenticator app. */
export function createTotpSecret() {
  return generateSecret();
}

/** otpauth:// URI that Google Authenticator reads from the QR code. */
export function buildOtpAuthUrl({ secret, accountName, issuer = config.issuer }) {
  return generateURI({ secret, label: accountName, issuer });
}

export async function makeQrDataUrl(otpauthUrl) {
  return QRCode.toDataURL(otpauthUrl, {
    errorCorrectionLevel: 'M',
    margin: 1,
    width: 240,
  });
}

/**
 * Verify a 6-digit TOTP code. `afterTimeStep` rejects codes that were already
 * used (or that are older than the last accepted step).
 */
export async function verifyTotp(secret, token, afterTimeStep = null) {
  const normalized = String(token ?? '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) {
    return { valid: false, reason: 'FORMAT' };
  }

  const result = await verify({
    secret,
    token: normalized,
    epoch: nowSeconds(),
    epochTolerance: config.totpToleranceSeconds,
    ...(afterTimeStep != null ? { afterTimeStep } : {}),
  });

  if (!result.valid) {
    return { valid: false, reason: 'INVALID' };
  }
  return { valid: true, timeStep: result.timeStep };
}

/** Only used by tests and local demos to obtain a code for a given moment. */
export async function generateTotp(secret, epoch = nowSeconds()) {
  return generate({ secret, epoch });
}

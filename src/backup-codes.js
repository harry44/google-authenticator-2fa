import bcrypt from 'bcryptjs';
import { randomInt } from 'node:crypto';
import { config } from './config.js';

// No 0/O or 1/I: easier to read off a printed sheet.
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function normalizeBackupCode(code) {
  return String(code ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/** Human-friendly codes such as K7M2P-9XQ4R. Returned in plaintext exactly once. */
export function generateBackupCodes(count = config.backupCodeCount) {
  return Array.from({ length: count }, () => {
    let raw = '';
    for (let i = 0; i < 10; i += 1) {
      raw += ALPHABET[randomInt(ALPHABET.length)];
    }
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
}

export function hashBackupCodes(codes) {
  return Promise.all(codes.map((code) => bcrypt.hash(normalizeBackupCode(code), config.bcryptRounds)));
}

/**
 * A backup code works once: on a match the hash is removed from the list.
 * Returns { valid, remaining } so the caller can persist the shortened list.
 */
export async function consumeBackupCode(hashes, code) {
  const normalized = normalizeBackupCode(code);
  if (normalized.length !== 10) {
    return { valid: false, remaining: hashes };
  }

  for (let i = 0; i < hashes.length; i += 1) {
    if (await bcrypt.compare(normalized, hashes[i])) {
      return {
        valid: true,
        remaining: hashes.slice(0, i).concat(hashes.slice(i + 1)),
      };
    }
  }
  return { valid: false, remaining: hashes };
}

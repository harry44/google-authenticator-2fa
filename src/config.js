const int = (value, fallback) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
};

export const config = {
  issuer: process.env.TOTP_ISSUER || 'GroovyGrails Demo',
  bcryptRounds: int(process.env.BCRYPT_ROUNDS, 12),
  // Accept the previous/next 30-second step so a slightly slow phone still works.
  totpToleranceSeconds: int(process.env.TOTP_TOLERANCE_SECONDS, 30),
  backupCodeCount: int(process.env.BACKUP_CODE_COUNT, 10),
  sessionTtlMs: int(process.env.SESSION_TTL_MINUTES, 60) * 60 * 1000,
  challengeTtlMs: int(process.env.CHALLENGE_TTL_MINUTES, 5) * 60 * 1000,
  challengeMaxAttempts: int(process.env.CHALLENGE_MAX_ATTEMPTS, 5),
};

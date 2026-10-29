let frozenEpoch = null;

/** Unix time in seconds; tests can freeze it for deterministic TOTP steps. */
export function nowSeconds() {
  return frozenEpoch ?? Math.floor(Date.now() / 1000);
}

export function freezeClock(epochSeconds) {
  frozenEpoch = epochSeconds;
}

export function unfreezeClock() {
  frozenEpoch = null;
}

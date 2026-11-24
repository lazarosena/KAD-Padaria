import crypto from 'crypto';

export const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const digest = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${digest}`;
}

export function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  const [algorithm, salt, digest, extra] = stored.split(':');
  if (algorithm !== 'scrypt' || !salt || !digest || extra || !/^[a-f0-9]{128}$/i.test(digest)) return false;

  const candidate = crypto.scryptSync(String(password), salt, 64);
  const expected = Buffer.from(digest, 'hex');
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

export function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

export function isValidISODate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

export function isSessionExpired(session, now = Date.now()) {
  return !session || session.expiresAt <= now;
}

export function parseFiniteNumber(value, label, { min = 0, max = 999999999 } = {}) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < min || number > max) {
    throw new Error(`${label} inválido`);
  }
  return number;
}

export function parsePositiveId(value, label = 'Identificador') {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) {
    throw new Error(`${label} inválido`);
  }
  return number;
}

export function parseText(value, label, maxLength = 120) {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > maxLength) {
    throw new Error(`${label} inválido`);
  }
  return value.trim();
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  hashPassword,
  isValidISODate,
  isSessionExpired,
  isValidPassword,
  parseFiniteNumber,
  parsePositiveId,
  parseText,
  verifyPassword
} from './security.js';

test('password hashes verify without storing plaintext', () => {
  const hash = hashPassword('UmaSenhaSegura123!');
  assert.notEqual(hash, 'UmaSenhaSegura123!');
  assert.equal(verifyPassword('UmaSenhaSegura123!', hash), true);
  assert.equal(verifyPassword('senha errada', hash), false);
  assert.equal(verifyPassword('senha', 'malformed'), false);
});

test('new passwords must be at least eight characters', () => {
  assert.equal(isValidPassword('admin123'), true);
  assert.equal(isValidPassword('SenhaCom14!abc'), true);
  assert.equal(isValidPassword('admin12'), false);
  assert.equal(isValidPassword('a'.repeat(129)), false);
});

test('sessions expire at their deadline', () => {
  assert.equal(isSessionExpired({ expiresAt: 2000 }, 1999), false);
  assert.equal(isSessionExpired({ expiresAt: 2000 }, 2000), true);
  assert.equal(isSessionExpired(null, 0), true);
});

test('calendar dates must exist in ISO format', () => {
  assert.equal(isValidISODate('2024-02-29'), true);
  assert.equal(isValidISODate('2025-02-29'), false);
  assert.equal(isValidISODate('2025-13-01'), false);
});

test('numeric and text inputs reject invalid values', () => {
  assert.equal(parseFiniteNumber('1.25', 'Valor'), 1.25);
  assert.throws(() => parseFiniteNumber('-1', 'Valor'));
  assert.throws(() => parseFiniteNumber('NaN', 'Valor'));
  assert.equal(parsePositiveId('12'), 12);
  assert.throws(() => parsePositiveId('0'));
  assert.equal(parseText('  Maria  ', 'Nome'), 'Maria');
  assert.throws(() => parseText(' ', 'Nome'));
});

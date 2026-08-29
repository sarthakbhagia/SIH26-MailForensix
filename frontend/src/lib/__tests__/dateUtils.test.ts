import test from 'node:test';
import assert from 'node:assert/strict';
import {
  safeParseDate,
  safeToISOString,
  safeFormatDate,
  safeFormatDateOnly,
  safeFormatDistanceToNow,
} from '../dateUtils.ts';

test('safeParseDate - parses valid date formats correctly', () => {
  const validIso = '2026-08-29T10:30:00';
  const parsed = safeParseDate(validIso);
  assert.ok(parsed instanceof Date, 'Should return a Date instance');
  assert.equal(isNaN(parsed.getTime()), false, 'Date timestamp should be valid');

  const validUtcIso = '2024-01-15T10:30:00.123Z';
  const parsedUtc = safeParseDate(validUtcIso);
  assert.ok(parsedUtc instanceof Date);
  assert.equal(isNaN(parsedUtc.getTime()), false);

  const timestamp = 1700000000000;
  const parsedNum = safeParseDate(timestamp);
  assert.ok(parsedNum instanceof Date);
  assert.equal(parsedNum.getTime(), timestamp);

  const now = new Date();
  const parsedDate = safeParseDate(now);
  assert.equal(parsedDate, now);
});

test('safeParseDate - safely returns null for null, undefined, and empty string', () => {
  assert.equal(safeParseDate(null), null);
  assert.equal(safeParseDate(undefined), null);
  assert.equal(safeParseDate(''), null);
  assert.equal(safeParseDate('   '), null);
});

test('safeParseDate - safely returns null for malformed date strings without throwing', () => {
  assert.doesNotThrow(() => {
    const res1 = safeParseDate('invalid-date');
    assert.equal(res1, null);

    const res2 = safeParseDate('2024-13-45T99:99:99');
    assert.equal(res2, null);

    const res3 = safeParseDate('not a date');
    assert.equal(res3, null);

    const res4 = safeParseDate(NaN);
    assert.equal(res4, null);

    const res5 = safeParseDate(new Date('invalid'));
    assert.equal(res5, null);
  });
});

test('safeToISOString - returns valid ISO string for valid date and NEVER throws RangeError', () => {
  const valid = '2026-08-29T10:30:00.000Z';
  assert.equal(safeToISOString(valid), valid);

  // Null / undefined inputs
  assert.doesNotThrow(() => {
    const isoNull = safeToISOString(null, 'FALLBACK_ISO');
    assert.equal(isoNull, 'FALLBACK_ISO');

    const isoUndefined = safeToISOString(undefined, 'FALLBACK_ISO');
    assert.equal(isoUndefined, 'FALLBACK_ISO');
  });

  // CRITICAL REGRESSION TEST: Invalid date string must NOT throw RangeError: Invalid time value
  assert.doesNotThrow(() => {
    const isoInvalid = safeToISOString('invalid-date');
    assert.ok(typeof isoInvalid === 'string', 'Should return a string');
    assert.ok(isoInvalid.length > 0, 'Should return non-empty ISO fallback');

    const customFallback = safeToISOString('malformed-date-string', '—');
    assert.equal(customFallback, '—');
  });
});

test('safeFormatDate - formats valid dates and handles invalid dates gracefully', () => {
  const valid = '2026-08-29T10:30:00.000Z';
  const formatted = safeFormatDate(valid);
  assert.ok(typeof formatted === 'string' && formatted.length > 0);

  // Missing or invalid
  assert.equal(safeFormatDate(null), '—');
  assert.equal(safeFormatDate(undefined), '—');
  assert.equal(safeFormatDate('invalid-date'), '—');
  assert.equal(safeFormatDate('invalid-date', 'N/A'), 'N/A');
});

test('safeFormatDateOnly - formats date-only and handles invalid dates gracefully', () => {
  const valid = '2026-08-29T10:30:00.000Z';
  const formatted = safeFormatDateOnly(valid);
  assert.ok(typeof formatted === 'string' && formatted.length > 0);

  assert.equal(safeFormatDateOnly(null), '—');
  assert.equal(safeFormatDateOnly(undefined), '—');
  assert.equal(safeFormatDateOnly('invalid-date'), '—');
});

test('safeFormatDistanceToNow - never throws RangeError on invalid date strings', () => {
  // Valid date string
  const recent = new Date(Date.now() - 60000).toISOString();
  const formatted = safeFormatDistanceToNow(recent, { addSuffix: true });
  assert.ok(formatted.includes('minute') || formatted.includes('ago') || formatted.length > 0);

  // Missing and malformed dates
  assert.doesNotThrow(() => {
    assert.equal(safeFormatDistanceToNow(null), '');
    assert.equal(safeFormatDistanceToNow(undefined), '');
    assert.equal(safeFormatDistanceToNow('invalid-date'), '');
    assert.equal(safeFormatDistanceToNow('invalid-date', { addSuffix: true }, 'recently'), 'recently');
  });
});

import { formatDistanceToNow } from 'date-fns';
import type { FormatDistanceToNowOptions } from 'date-fns';

/**
 * Safely parses any value into a valid Date object.
 * Returns null if the value is null, undefined, empty, or unparseable.
 * Logs a warning in console if a non-empty string is provided that cannot be parsed as a valid date.
 */
export function safeParseDate(val: unknown): Date | null {
  if (val === null || val === undefined) {
    return null;
  }

  if (val instanceof Date) {
    return isNaN(val.getTime()) ? null : val;
  }

  if (typeof val === 'number') {
    if (isNaN(val) || !isFinite(val)) return null;
    const d = new Date(val);
    return isNaN(d.getTime()) ? null : d;
  }

  if (typeof val === 'string') {
    const trimmed = val.trim();
    if (!trimmed) return null;
    const d = new Date(trimmed);
    if (!isNaN(d.getTime())) {
      return d;
    }
    // Avoid silent hiding of malformed backend dates while preventing crashes
    console.warn(`[dateUtils] Unparseable date string encountered: "${val}"`);
    return null;
  }

  return null;
}

/**
 * Returns an ISO 8601 string representation of the date.
 * Guaranteed to NEVER throw RangeError: Invalid time value.
 *
 * @param val The date input (string, Date, number, null, undefined)
 * @param fallback Optional fallback string if the date is invalid (defaults to current ISO timestamp)
 */
export function safeToISOString(val: unknown, fallback?: string): string {
  const d = safeParseDate(val);
  if (d) {
    return d.toISOString();
  }
  return fallback !== undefined ? fallback : new Date().toISOString();
}

/**
 * Formats a date into a localized string using toLocaleString().
 * Guaranteed to never crash on invalid inputs.
 *
 * @param val The date input
 * @param fallback Fallback string if date is missing or invalid (defaults to '—')
 */
export function safeFormatDate(val: unknown, fallback: string = '—'): string {
  const d = safeParseDate(val);
  if (d) {
    try {
      return d.toLocaleString();
    } catch {
      return fallback;
    }
  }
  return fallback;
}

/**
 * Formats a date into a localized date-only string using toLocaleDateString().
 */
export function safeFormatDateOnly(val: unknown, fallback: string = '—'): string {
  const d = safeParseDate(val);
  if (d) {
    try {
      return d.toLocaleDateString();
    } catch {
      return fallback;
    }
  }
  return fallback;
}

/**
 * Safely computes distance to now using date-fns formatDistanceToNow.
 * Guaranteed to never throw on invalid dates.
 *
 * @param val The date input
 * @param options date-fns FormatDistanceToNowOptions (e.g. { addSuffix: true })
 * @param fallback Fallback string if date is missing or invalid (defaults to '')
 */
export function safeFormatDistanceToNow(
  val: unknown,
  options?: FormatDistanceToNowOptions,
  fallback: string = ''
): string {
  const d = safeParseDate(val);
  if (!d) return fallback;
  try {
    return formatDistanceToNow(d, options);
  } catch (err) {
    console.warn('[dateUtils] formatDistanceToNow failed for valid date:', err);
    return fallback;
  }
}

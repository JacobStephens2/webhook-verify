import { timingSafeEqual } from 'node:crypto';

/**
 * Constant-time string comparison. Length differences return false
 * immediately — length is not a secret in any scheme here.
 */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

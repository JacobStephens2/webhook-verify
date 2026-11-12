import { createHmac } from 'node:crypto';

/** HMAC-SHA256 hex of the Timestamped signing base; see ../GLOSSARY.md. */
export function timestampedDigest(
  rawBody: string | Buffer,
  secret: string,
  timestampSeconds: number,
): string {
  return createHmac('sha256', secret)
    .update(`${timestampSeconds}.`, 'utf8')
    .update(rawBody)
    .digest('hex');
}

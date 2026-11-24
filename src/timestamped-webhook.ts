import { createHmac } from 'node:crypto';
import { safeEqual } from './safe-equal.js';

export interface TimestampedVerifyOptions {
  /** Maximum allowed age (and future clock skew) in seconds. Default 300. */
  toleranceSeconds?: number;
  /** Injectable clock for tests, as a unix timestamp in seconds. */
  nowSeconds?: number;
}

/** HMAC-SHA256 hex of the Timestamped signing base; see ../GLOSSARY.md. */
function timestampedDigest(
  rawBody: string | Buffer,
  secret: string,
  timestampSeconds: number,
): string {
  return createHmac('sha256', secret)
    .update(`${timestampSeconds}.`, 'utf8')
    .update(rawBody)
    .digest('hex');
}

/**
 * Timestamped dialect, producer side: Stripe-style `t=<unix>,v1=<hex>`
 * where the signed payload is `"<t>.<rawBody>"`. The timestamp is what
 * gives the receiver a replay defense. Throws an {@link Error} if
 * `timestampSeconds` is not an integer.
 */
export function signTimestamped(
  rawBody: string | Buffer,
  secret: string,
  timestampSeconds: number,
): string {
  if (!Number.isInteger(timestampSeconds)) {
    throw new Error('timestampSeconds must be an integer');
  }
  const signature = timestampedDigest(rawBody, secret, timestampSeconds);
  return `t=${timestampSeconds},v1=${signature}`;
}

type TimestampedAssessment = 'verified' | 'missing' | 'rejected';

function assessTimestamped(
  rawBody: string | Buffer,
  header: string | null | undefined,
  secret: string,
  options: TimestampedVerifyOptions,
  whitespaceOnlyHeaderPolicy: 'treat-as-missing' | 'check-as-present',
): TimestampedAssessment {
  if (
    !header ||
    (whitespaceOnlyHeaderPolicy === 'treat-as-missing' &&
      typeof header === 'string' &&
      header.trim() === '')
  ) {
    return 'missing';
  }
  const { toleranceSeconds = 300 } = options;
  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);

  let timestamp: number | undefined;
  const candidates: string[] = [];
  for (const part of header.split(',')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === 't') timestamp = Number(value);
    else if (key === 'v1') candidates.push(value);
  }
  if (timestamp === undefined || !Number.isInteger(timestamp) || candidates.length === 0) {
    return 'rejected';
  }
  if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) return 'rejected';

  const expected = timestampedDigest(rawBody, secret, timestamp);
  return candidates.some((candidate) => safeEqual(expected, candidate)) ? 'verified' : 'rejected';
}

/**
 * Timestamped dialect, receiver side. Accepts multiple `v1` entries in one
 * header (sent during key rotation); any single match passes. Rejects
 * non-integer timestamps and timestamps outside the tolerance window in either
 * direction.
 */
export function verifyTimestamped(
  rawBody: string | Buffer,
  header: string | null | undefined,
  secret: string,
  options: TimestampedVerifyOptions = {},
): boolean {
  return assessTimestamped(rawBody, header, secret, options, 'check-as-present') === 'verified';
}

/**
 * Stripe's `Stripe-Signature` header. Same construction as
 * {@link verifyTimestamped}: HMAC-SHA256 hex over `"<t>.<rawBody>"`, keyed
 * with the endpoint secret as a UTF-8 string (including the `whsec_` prefix,
 * matching the Stripe SDKs). Use this when you already have the Stripe client
 * for Checkout/API work but want verification without
 * `stripe.webhooks.constructEvent`.
 */
export function verifyStripe(
  rawBody: string | Buffer,
  header: string | null | undefined,
  secret: string,
  options: TimestampedVerifyOptions = {},
): boolean {
  return verifyTimestamped(rawBody, header, secret, options);
}

/** Thrown by {@link constructStripeEvent} when the signature is missing or invalid. */
export class WebhookSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebhookSignatureError';
  }
}

/**
 * Verify a Stripe webhook signature and return the parsed JSON body.
 *
 * Drop-in shape for call sites that previously used
 * `stripe.webhooks.constructEvent`: still pass the *raw* request body (Buffer
 * or string — never a re-serialized parse), the `Stripe-Signature` header, and
 * the `whsec_…` secret. Throws {@link WebhookSignatureError} on failure so
 * handlers can 400 the same way.
 *
 * This only verifies and parses. Typing the result as `Stripe.Event` and
 * handling event types remains the app's job (and usually still uses the
 * `stripe` package for Checkout, Portal, and API refetch).
 */
export function constructStripeEvent(
  rawBody: string | Buffer,
  header: string | null | undefined,
  secret: string,
  options: TimestampedVerifyOptions = {},
): unknown {
  const assessment = assessTimestamped(rawBody, header, secret, options, 'treat-as-missing');
  if (assessment === 'missing') {
    throw new WebhookSignatureError('Missing Stripe-Signature header');
  }
  if (assessment !== 'verified') {
    throw new WebhookSignatureError(
      'Invalid Stripe signature or timestamp outside tolerance',
    );
  }
  const body = typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8');
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new WebhookSignatureError('Webhook body is not valid JSON');
  }
}

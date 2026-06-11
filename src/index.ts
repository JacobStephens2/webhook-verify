import { createHmac, timingSafeEqual } from 'node:crypto';

export type HmacAlgorithm = 'sha1' | 'sha256' | 'sha512';
export type SignatureEncoding = 'hex' | 'base64';

export interface BodySignatureOptions {
  /** HMAC hash. Default `'sha256'`. */
  algorithm?: HmacAlgorithm;
  /** Digest encoding of the signature string. Default `'hex'`. */
  encoding?: SignatureEncoding;
}

export interface TimestampedVerifyOptions {
  /** Maximum allowed age (and future clock skew) in seconds. Default 300. */
  toleranceSeconds?: number;
  /** Injectable clock for tests, as a unix timestamp in seconds. */
  nowSeconds?: number;
}

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

function hmacDigest(
  data: string | Buffer,
  secret: string,
  algorithm: HmacAlgorithm,
  encoding: SignatureEncoding,
): string {
  return createHmac(algorithm, secret).update(data).digest(encoding);
}

/**
 * Raw-body dialect, producer side: HMAC over the exact bytes you send.
 * Pair with `verifyBody` on the receiving service.
 */
export function signBody(
  rawBody: string | Buffer,
  secret: string,
  options: BodySignatureOptions = {},
): string {
  const { algorithm = 'sha256', encoding = 'hex' } = options;
  return hmacDigest(rawBody, secret, algorithm, encoding);
}

/**
 * Raw-body dialect, receiver side. `rawBody` must be the unparsed request
 * bytes — verifying a re-serialized parse is the classic way this fails.
 */
export function verifyBody(
  rawBody: string | Buffer,
  signature: string | null | undefined,
  secret: string,
  options: BodySignatureOptions = {},
): boolean {
  if (!signature) return false;
  return safeEqual(signBody(rawBody, secret, options), signature);
}

/**
 * GitHub's `X-Hub-Signature-256` header: `sha256=` + hex HMAC-SHA256 of the
 * raw body, keyed with the webhook secret.
 */
export function verifyGitHub(
  rawBody: string | Buffer,
  header: string | null | undefined,
  secret: string,
): boolean {
  if (!header || !header.startsWith('sha256=')) return false;
  return verifyBody(rawBody, header.slice('sha256='.length), secret);
}

/**
 * Timestamped dialect, producer side: Stripe-style `t=<unix>,v1=<hex>`
 * where the signed payload is `"<t>.<rawBody>"`. The timestamp is what
 * gives the receiver a replay defense.
 */
export function signTimestamped(
  rawBody: string | Buffer,
  secret: string,
  timestampSeconds: number,
): string {
  const body = typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8');
  const signature = hmacDigest(`${timestampSeconds}.${body}`, secret, 'sha256', 'hex');
  return `t=${timestampSeconds},v1=${signature}`;
}

/**
 * Timestamped dialect, receiver side. Accepts multiple `v1` entries in one
 * header (sent during key rotation); any single match passes. Rejects
 * timestamps outside the tolerance window in either direction.
 */
export function verifyTimestamped(
  rawBody: string | Buffer,
  header: string | null | undefined,
  secret: string,
  options: TimestampedVerifyOptions = {},
): boolean {
  if (!header) return false;
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
  if (timestamp === undefined || !Number.isFinite(timestamp) || candidates.length === 0) {
    return false;
  }
  if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) return false;

  const body = typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8');
  const expected = hmacDigest(`${timestamp}.${body}`, secret, 'sha256', 'hex');
  return candidates.some((candidate) => safeEqual(expected, candidate));
}

/**
 * The base both Twilio and Mandrill sign: the public webhook URL with every
 * POST param appended in key order, as `key` then `value`, no separators.
 */
function urlParamsBase(url: string, params: Record<string, string>): string {
  let data = url;
  for (const key of Object.keys(params).sort()) {
    data += key + params[key];
  }
  return data;
}

/**
 * Twilio's `X-Twilio-Signature`: base64 HMAC-SHA1 over the URL + sorted
 * params base, keyed with the account's auth token. `url` must be the
 * public URL Twilio called, query string included — not what your app
 * sees behind a proxy.
 */
export function verifyTwilio(
  url: string,
  params: Record<string, string>,
  header: string | null | undefined,
  authToken: string,
): boolean {
  if (!header) return false;
  const expected = hmacDigest(urlParamsBase(url, params), authToken, 'sha1', 'base64');
  return safeEqual(expected, header);
}

/**
 * Mandrill's `X-Mandrill-Signature`: same construction as Twilio's, keyed
 * with the webhook key from the Mandrill webhook settings page. The signed
 * URL is the webhook URL exactly as configured in Mandrill.
 */
export function verifyMandrill(
  url: string,
  params: Record<string, string>,
  header: string | null | undefined,
  webhookKey: string,
): boolean {
  if (!header) return false;
  const expected = hmacDigest(urlParamsBase(url, params), webhookKey, 'sha1', 'base64');
  return safeEqual(expected, header);
}

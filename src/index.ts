import { createHmac } from 'node:crypto';
import { safeEqual } from './safe-equal.js';

export { safeEqual } from './safe-equal.js';
export {
  constructStripeEvent,
  signTimestamped,
  verifyStripe,
  verifyTimestamped,
  WebhookSignatureError,
  type TimestampedVerifyOptions,
} from './timestamped-webhook.js';

export type HmacAlgorithm = 'sha1' | 'sha256' | 'sha512';
export type SignatureEncoding = 'hex' | 'base64';

export interface BodySignatureOptions {
  /** HMAC hash. Default `'sha256'`. */
  algorithm?: HmacAlgorithm;
  /** Digest encoding of the signature string. Default `'hex'`. */
  encoding?: SignatureEncoding;
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
 * URL + sorted params verification: HMAC-SHA1/base64 over the exact public
 * URL followed by each own enumerable param's key and value in default
 * JavaScript lexicographic key order, without separators.
 */
function verifyUrlParams(
  url: string,
  params: Record<string, string>,
  header: string | null | undefined,
  secret: string,
): boolean {
  if (!header) return false;
  let data = url;
  for (const key of Object.keys(params).sort()) {
    data += key + params[key];
  }
  const expected = hmacDigest(data, secret, 'sha1', 'base64');
  return safeEqual(expected, header);
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
  return verifyUrlParams(url, params, header, authToken);
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
  return verifyUrlParams(url, params, header, webhookKey);
}

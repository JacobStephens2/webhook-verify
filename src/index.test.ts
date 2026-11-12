import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  safeEqual,
  signBody,
  signTimestamped,
  verifyBody,
  verifyGitHub,
  verifyMandrill,
  verifyTimestamped,
  verifyTwilio,
  verifyStripe,
  constructStripeEvent,
  WebhookSignatureError,
} from './index.js';

const SECRET = 'whsec_test_4f8a2b';

function independentTimestampedHeader(
  rawBody: string | Buffer,
  secret: string,
  timestamp: number,
): string {
  const signingBase = Buffer.concat([
    Buffer.from(`${timestamp}.`, 'utf8'),
    typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody,
  ]);
  const digest = createHmac('sha256', secret).update(signingBase).digest('hex');
  return `t=${timestamp},v1=${digest}`;
}

describe('safeEqual', () => {
  it('matches equal strings', () => {
    expect(safeEqual('abc123', 'abc123')).toBe(true);
  });

  it('rejects differing strings of equal length', () => {
    expect(safeEqual('abc123', 'abc124')).toBe(false);
  });

  it('rejects strings of different length', () => {
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });

  it('matches empty strings', () => {
    expect(safeEqual('', '')).toBe(true);
  });
});

describe('signBody / verifyBody', () => {
  const body = '{"event":"settlement.complete","amount":1250}';

  it('round-trips with defaults (sha256 hex)', () => {
    const sig = signBody(body, SECRET);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyBody(body, sig, SECRET)).toBe(true);
  });

  it('round-trips sha1 base64', () => {
    const opts = { algorithm: 'sha1', encoding: 'base64' } as const;
    const sig = signBody(body, SECRET, opts);
    expect(verifyBody(body, sig, SECRET, opts)).toBe(true);
  });

  it('treats Buffer and string bodies identically', () => {
    expect(signBody(Buffer.from(body, 'utf8'), SECRET)).toBe(signBody(body, SECRET));
  });

  it('signs multi-byte UTF-8 consistently', () => {
    const utf8 = '{"name":"Sébastien — naïve"}';
    expect(verifyBody(utf8, signBody(utf8, SECRET), SECRET)).toBe(true);
  });

  it('rejects a tampered body', () => {
    const sig = signBody(body, SECRET);
    expect(verifyBody(body.replace('1250', '9250'), sig, SECRET)).toBe(false);
  });

  it('rejects the wrong secret', () => {
    expect(verifyBody(body, signBody(body, SECRET), 'other-secret')).toBe(false);
  });

  it('rejects a missing signature', () => {
    expect(verifyBody(body, undefined, SECRET)).toBe(false);
    expect(verifyBody(body, null, SECRET)).toBe(false);
    expect(verifyBody(body, '', SECRET)).toBe(false);
  });
});

describe('verifyGitHub', () => {
  const body = '{"action":"opened","number":7}';
  const header = 'sha256=' + createHmac('sha256', SECRET).update(body).digest('hex');

  it('accepts a valid X-Hub-Signature-256 header', () => {
    expect(verifyGitHub(body, header, SECRET)).toBe(true);
  });

  it('rejects a header without the sha256= prefix', () => {
    expect(verifyGitHub(body, header.slice('sha256='.length), SECRET)).toBe(false);
  });

  it('rejects a tampered body and a missing header', () => {
    expect(verifyGitHub(body + ' ', header, SECRET)).toBe(false);
    expect(verifyGitHub(body, undefined, SECRET)).toBe(false);
  });
});

describe('signTimestamped / verifyTimestamped', () => {
  const body = '{"id":"evt_123","type":"charge.succeeded"}';
  const now = 1_750_000_000;

  it('signs distinct Buffer bytes against independent HMAC vectors', () => {
    const bodies = ['80', '81', 'efbfbd'].map((hex) => Buffer.from(hex, 'hex'));
    const headers = bodies.map((rawBody) => signTimestamped(rawBody, SECRET, now));
    const expected = bodies.map((rawBody) => independentTimestampedHeader(rawBody, SECRET, now));

    expect(headers).toEqual(expected);
    expect(new Set(headers).size).toBe(3);
  });

  it.each([
    { name: 'verifyTimestamped', verify: verifyTimestamped },
    { name: 'verifyStripe', verify: verifyStripe },
  ])('$name verifies each independent Buffer header only against its exact body bytes', ({ verify }) => {
    const bodies = ['80', '81', 'efbfbd'].map((hex) => Buffer.from(hex, 'hex'));
    for (const signedBody of bodies) {
      const header = independentTimestampedHeader(signedBody, SECRET, now);
      for (const receivedBody of bodies) {
        expect(verify(receivedBody, header, SECRET, { nowSeconds: now }))
          .toBe(receivedBody.equals(signedBody));
      }
    }
  });

  it('rejects formerly lossy headers for non-UTF-8 bodies', () => {
    for (const hex of ['80', '81']) {
      const rawBody = Buffer.from(hex, 'hex');
      const lossyHeader = independentTimestampedHeader(rawBody.toString('utf8'), SECRET, now);
      expect(verifyTimestamped(rawBody, lossyHeader, SECRET, { nowSeconds: now })).toBe(false);
    }
  });

  it.each(['', 'ASCII body', 'Sébastien — naïve 🚀', 'before\0after'])(
    'preserves UTF-8 string and Buffer signatures for %j',
    (rawBody) => {
      const header = independentTimestampedHeader(rawBody, SECRET, now);
      for (const input of [rawBody, Buffer.from(rawBody, 'utf8')]) {
        expect(signTimestamped(input, SECRET, now)).toBe(header);
        expect(verifyTimestamped(input, header, SECRET, { nowSeconds: now })).toBe(true);
      }
    },
  );

  it('keeps using the parsed numeric timestamp and the last timestamp field', () => {
    const rawBody = Buffer.from('80', 'hex');
    const header = independentTimestampedHeader(rawBody, SECRET, now)
      .replace(`t=${now}`, 'ignored,t=0,t=1.75e9');
    expect(verifyTimestamped(rawBody, header, SECRET, { nowSeconds: now })).toBe(true);
  });

  it('round-trips within the tolerance window', () => {
    const header = signTimestamped(body, SECRET, now);
    expect(header).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(verifyTimestamped(body, header, SECRET, { nowSeconds: now + 60 })).toBe(true);
  });

  it('rejects a timestamp older than the tolerance', () => {
    const header = signTimestamped(body, SECRET, now);
    expect(verifyTimestamped(body, header, SECRET, { nowSeconds: now + 301 })).toBe(false);
  });

  it('rejects a timestamp too far in the future (clock skew bound)', () => {
    const header = signTimestamped(body, SECRET, now + 400);
    expect(verifyTimestamped(body, header, SECRET, { nowSeconds: now })).toBe(false);
  });

  it('honors a custom tolerance', () => {
    const header = signTimestamped(body, SECRET, now);
    expect(verifyTimestamped(body, header, SECRET, { nowSeconds: now + 500, toleranceSeconds: 600 })).toBe(true);
  });

  it('accepts any one of multiple v1 entries (key rotation)', () => {
    const valid = signTimestamped(body, SECRET, now).split('v1=')[1];
    const header = `t=${now},v1=${'0'.repeat(64)},v1=${valid}`;
    expect(verifyTimestamped(body, header, SECRET, { nowSeconds: now })).toBe(true);
  });

  it('rejects when the timestamp in the header was altered', () => {
    const header = signTimestamped(body, SECRET, now).replace(`t=${now}`, `t=${now + 10}`);
    expect(verifyTimestamped(body, header, SECRET, { nowSeconds: now })).toBe(false);
  });

  it('rejects malformed and missing headers', () => {
    expect(verifyTimestamped(body, undefined, SECRET, { nowSeconds: now })).toBe(false);
    expect(verifyTimestamped(body, 'not-a-signature', SECRET, { nowSeconds: now })).toBe(false);
    expect(verifyTimestamped(body, 't=soon,v1=' + '0'.repeat(64), SECRET, { nowSeconds: now })).toBe(false);
    expect(verifyTimestamped(body, `t=${now}`, SECRET, { nowSeconds: now })).toBe(false);
  });
});

describe('verifyStripe / constructStripeEvent', () => {
  const body = '{"id":"evt_test","object":"event","type":"invoice.paid"}';
  const now = 1_750_000_000;
  // Stripe secrets look like this; the full string (including whsec_) is the HMAC key.
  const stripeSecret = 'whsec_test_chart35_endpoint_secret';

  it('constructStripeEvent parses a JSON Buffer with an independent header', () => {
    const rawBody = Buffer.from('{"id":"evt_🚀","text":"Sébastien","nul":"\\u0000"}', 'utf8');
    const header = independentTimestampedHeader(rawBody, stripeSecret, now);
    expect(constructStripeEvent(rawBody, header, stripeSecret, { nowSeconds: now }))
      .toEqual({ id: 'evt_🚀', text: 'Sébastien', nul: '\0' });
  });

  it('constructStripeEvent verifies Buffer bytes before parsing and retains signature errors', () => {
    const rawBody = Buffer.from('80', 'hex');
    const header = independentTimestampedHeader(rawBody, stripeSecret, now);
    const invalidSignature = () =>
      constructStripeEvent(rawBody, header, 'whsec_wrong', { nowSeconds: now });
    const invalidJson = () =>
      constructStripeEvent(rawBody, header, stripeSecret, { nowSeconds: now });

    expect(invalidSignature).toThrow(WebhookSignatureError);
    expect(invalidSignature).toThrow('Invalid Stripe signature or timestamp outside tolerance');
    expect(invalidJson).toThrow(WebhookSignatureError);
    expect(invalidJson).toThrow('Webhook body is not valid JSON');
  });

  it('verifyStripe accepts a Stripe-style header (alias of verifyTimestamped)', () => {
    const header = signTimestamped(body, stripeSecret, now);
    expect(verifyStripe(body, header, stripeSecret, { nowSeconds: now })).toBe(true);
    expect(verifyStripe(Buffer.from(body, 'utf8'), header, stripeSecret, { nowSeconds: now })).toBe(true);
  });

  it('constructStripeEvent returns the parsed JSON on success', () => {
    const header = signTimestamped(body, stripeSecret, now);
    const event = constructStripeEvent(body, header, stripeSecret, { nowSeconds: now }) as {
      id: string;
      type: string;
    };
    expect(event.id).toBe('evt_test');
    expect(event.type).toBe('invoice.paid');
  });

  it('constructStripeEvent throws WebhookSignatureError on bad signature', () => {
    const header = signTimestamped(body, stripeSecret, now);
    expect(() =>
      constructStripeEvent(body, header, 'whsec_wrong', { nowSeconds: now }),
    ).toThrow(WebhookSignatureError);
    expect(() =>
      constructStripeEvent(body, undefined, stripeSecret, { nowSeconds: now }),
    ).toThrow(/Missing/);
  });

  it('constructStripeEvent rejects a re-serialized body (classic footgun)', () => {
    const header = signTimestamped(body, stripeSecret, now);
    // Pretty-print changes bytes → signature fails.
    const reserialized = JSON.stringify(JSON.parse(body), null, 2);
    expect(() =>
      constructStripeEvent(reserialized, header, stripeSecret, { nowSeconds: now }),
    ).toThrow(WebhookSignatureError);
  });
});

function twilioStyleSignature(url: string, params: Record<string, string>, key: string): string {
  let data = url;
  for (const k of Object.keys(params).sort()) data += k + params[k];
  return createHmac('sha1', key).update(data).digest('base64');
}

describe('verifyTwilio', () => {
  const url = 'https://app.example.com/sms/status?source=twilio';
  const params = { MessageSid: 'SM1234', MessageStatus: 'delivered', To: '+15551230000' };
  const authToken = 'twilio-auth-token';
  const header = twilioStyleSignature(url, params, authToken);

  it('accepts a valid signature regardless of param insertion order', () => {
    expect(verifyTwilio(url, params, header, authToken)).toBe(true);
    const reordered = { To: '+15551230000', MessageStatus: 'delivered', MessageSid: 'SM1234' };
    expect(verifyTwilio(url, reordered, header, authToken)).toBe(true);
  });

  it('rejects a tampered param value', () => {
    expect(verifyTwilio(url, { ...params, MessageStatus: 'failed' }, header, authToken)).toBe(false);
  });

  it('rejects a different URL (the proxy gotcha)', () => {
    expect(verifyTwilio('http://internal:8080/sms/status?source=twilio', params, header, authToken)).toBe(false);
  });

  it('rejects the wrong auth token and a missing header', () => {
    expect(verifyTwilio(url, params, header, 'wrong-token')).toBe(false);
    expect(verifyTwilio(url, params, undefined, authToken)).toBe(false);
  });
});

describe('verifyMandrill', () => {
  const url = 'https://app.example.com/webhooks/mandrill';
  const params = { mandrill_events: '[{"event":"open","_id":"abc123"}]' };
  const webhookKey = 'mandrill-webhook-key';
  const header = twilioStyleSignature(url, params, webhookKey);

  it('accepts a valid X-Mandrill-Signature', () => {
    expect(verifyMandrill(url, params, header, webhookKey)).toBe(true);
  });

  it('rejects tampered events, the wrong key, and a missing header', () => {
    expect(verifyMandrill(url, { mandrill_events: '[]' }, header, webhookKey)).toBe(false);
    expect(verifyMandrill(url, params, header, 'wrong-key')).toBe(false);
    expect(verifyMandrill(url, params, null, webhookKey)).toBe(false);
  });
});

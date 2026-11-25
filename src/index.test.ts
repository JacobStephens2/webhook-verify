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
  headerTimestamp = String(timestamp),
): string {
  const signingBase = Buffer.concat([
    Buffer.from(`${timestamp}.`, 'utf8'),
    typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody,
  ]);
  const digest = createHmac('sha256', secret).update(signingBase).digest('hex');
  return `t=${headerTimestamp},v1=${digest}`;
}

function independentTimestampedHeaderForTimestamp(
  rawBody: string | Buffer,
  secret: string,
  timestamp: string,
): string {
  const signingBase = Buffer.concat([
    Buffer.from(`${timestamp}.`, 'utf8'),
    typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody,
  ]);
  const digest = createHmac('sha256', secret).update(signingBase).digest('hex');
  return `t=${timestamp},v1=${digest}`;
}

function nonIntegerTimestampedHeaders(
  rawBody: string | Buffer,
  secret: string,
  baseTimestamp: number,
): string[] {
  const fractional = baseTimestamp + 0.5;
  return [
    independentTimestampedHeader(rawBody, secret, fractional),
    independentTimestampedHeader(rawBody, secret, fractional, fractional.toExponential()),
  ];
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

  it.each([now + 0.5, -1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    'signTimestamped rejects non-integer timestampSeconds %s',
    (invalidTimestamp) => {
      expect(() => signTimestamped(body, SECRET, invalidTimestamp)).toThrow(Error);
    },
  );

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

  it('uses the last timestamp field when it is canonical', () => {
    const rawBody = Buffer.from('80', 'hex');
    const header = independentTimestampedHeader(rawBody, SECRET, now)
      .replace(`t=${now}`, `t=0,t=${now}`);
    expect(verifyTimestamped(rawBody, header, SECRET, { nowSeconds: now })).toBe(true);
  });

  it('rejects non-canonical timestamp spellings that parse as integers', () => {
    const spellings = [
      '1.75e9',
      '1750000000.0',
      '1750000000.',
      '+1750000000',
      '01750000000',
      '1750000000e0',
      '',
      '-0',
      '0x10',
      '-1e2',
      '-0100',
      '00',
      '+0',
      '0.0',
    ];
    for (const spelling of spellings) {
      const timestamp = Number(spelling);
      expect(Number.isInteger(timestamp), spelling).toBe(true);
      const header = independentTimestampedHeader(body, SECRET, timestamp, spelling);
      expect(verifyTimestamped(body, header, SECRET, { nowSeconds: timestamp }), spelling).toBe(false);
      expect(verifyStripe(body, header, SECRET, { nowSeconds: timestamp }), spelling).toBe(false);
      expect(
        () => constructStripeEvent(body, header, SECRET, { nowSeconds: timestamp }),
        spelling,
      ).toThrow('Invalid Stripe signature or timestamp outside tolerance');
    }

    const earlierCanonical = independentTimestampedHeader(body, SECRET, now)
      .replace(`t=${now}`, `t=${now},t=1.75e9`);
    expect(verifyTimestamped(body, earlierCanonical, SECRET, { nowSeconds: now })).toBe(false);

    expect(verifyTimestamped(body, independentTimestampedHeader(body, SECRET, 0), SECRET, { nowSeconds: 0 })).toBe(true);
    expect(verifyTimestamped(body, independentTimestampedHeader(body, SECRET, 1), SECRET, { nowSeconds: 1 })).toBe(true);
    expect(verifyTimestamped(body, independentTimestampedHeader(body, SECRET, -1), SECRET, { nowSeconds: -1 })).toBe(true);
    expect(verifyTimestamped(body, independentTimestampedHeader(body, SECRET, -100), SECRET, { nowSeconds: -100 })).toBe(true);
  });

  it('uses the exact canonical timestamp string in the signing base', () => {
    const rawBody = Buffer.from('{"id":"evt_exact"}', 'utf8');
    // 2^53 + 1. Parsing it as a number rounds to a different decimal string.
    const exact = '9007199254740993';
    const parsed = String(Number(exact));
    expect(Number.isInteger(Number(exact))).toBe(true);
    expect(parsed).not.toBe(exact);

    const nowSeconds = Number(exact);
    const exactHeader = independentTimestampedHeaderForTimestamp(rawBody, SECRET, exact);
    const parsedHeader = independentTimestampedHeader(rawBody, SECRET, nowSeconds, exact);

    expect(verifyTimestamped(rawBody, exactHeader, SECRET, { nowSeconds })).toBe(true);
    expect(verifyTimestamped(rawBody, parsedHeader, SECRET, { nowSeconds })).toBe(false);
    expect(verifyStripe(rawBody, exactHeader, SECRET, { nowSeconds })).toBe(true);
    expect(constructStripeEvent(rawBody, exactHeader, SECRET, { nowSeconds })).toEqual({
      id: 'evt_exact',
    });
    expect(() => constructStripeEvent(rawBody, parsedHeader, SECRET, { nowSeconds })).toThrow(
      'Invalid Stripe signature or timestamp outside tolerance',
    );
  });

  it.each([
    { name: 'verifyTimestamped', verify: verifyTimestamped },
    { name: 'verifyStripe', verify: verifyStripe },
  ])('$name rejects non-integer timestamps even with a valid signature', ({ verify }) => {
    for (const header of nonIntegerTimestampedHeaders(body, SECRET, now)) {
      expect(verify(body, header, SECRET, { nowSeconds: now })).toBe(false);
    }
    expect(verify(body, independentTimestampedHeader(body, SECRET, Number.NaN), SECRET, { nowSeconds: now })).toBe(false);
    expect(verify(body, independentTimestampedHeader(body, SECRET, Number.POSITIVE_INFINITY), SECRET, { nowSeconds: now, toleranceSeconds: Infinity })).toBe(false);
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

  it('rejects malformed headers', () => {
    expect(verifyTimestamped(body, 'not-a-signature', SECRET, { nowSeconds: now })).toBe(false);
    expect(verifyTimestamped(body, 't=soon,v1=' + '0'.repeat(64), SECRET, { nowSeconds: now })).toBe(false);
    expect(verifyTimestamped(body, `t=${now}`, SECRET, { nowSeconds: now })).toBe(false);
  });
});

describe('Timestamped webhook header handling', () => {
  const body = '{"id":"evt_test"}';
  const headers = [
    { name: 'undefined', header: undefined, booleanOptionReads: [] },
    { name: 'null', header: null, booleanOptionReads: [] },
    { name: 'empty', header: '', booleanOptionReads: [] },
    { name: 'whitespace-only', header: ' \t\r\n', booleanOptionReads: ['toleranceSeconds', 'nowSeconds'] },
  ];

  function observeOptionReads() {
    const reads: string[] = [];
    const options = {
      get toleranceSeconds() {
        reads.push('toleranceSeconds');
        return 300;
      },
      get nowSeconds() {
        reads.push('nowSeconds');
        return 1_750_000_000;
      },
    };
    return { options, reads };
  }

  describe.each([
    { name: 'verifyTimestamped', verify: verifyTimestamped },
    { name: 'verifyStripe', verify: verifyStripe },
  ])('$name', ({ verify }) => {
    it.each(headers)('returns false for a $name header with the expected option reads', ({ header, booleanOptionReads }) => {
      const { options, reads } = observeOptionReads();
      expect(verify(body, header, SECRET, options)).toBe(false);
      expect(reads).toEqual(booleanOptionReads);
    });
  });

  it.each(headers)('constructStripeEvent reports a $name header as missing before reading options', ({ header }) => {
    const { options, reads } = observeOptionReads();
    const construct = () => constructStripeEvent(body, header, SECRET, options);
    expect(construct).toThrow(WebhookSignatureError);
    expect(construct).toThrow(/^Missing Stripe-Signature header$/);
    expect(reads).toEqual([]);
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
  });

  it('constructStripeEvent rejects a re-serialized body (classic footgun)', () => {
    const header = signTimestamped(body, stripeSecret, now);
    // Pretty-print changes bytes → signature fails.
    const reserialized = JSON.stringify(JSON.parse(body), null, 2);
    expect(() =>
      constructStripeEvent(reserialized, header, stripeSecret, { nowSeconds: now }),
    ).toThrow(WebhookSignatureError);
  });

  it('constructStripeEvent throws WebhookSignatureError for non-integer timestamps', () => {
    for (const header of nonIntegerTimestampedHeaders(body, stripeSecret, now)) {
      const attempt = () => constructStripeEvent(body, header, stripeSecret, { nowSeconds: now });
      expect(attempt).toThrow(WebhookSignatureError);
      expect(attempt).toThrow('Invalid Stripe signature or timestamp outside tolerance');
    }
  });
});

describe.each([
  { name: 'verifyTwilio', verify: verifyTwilio },
  { name: 'verifyMandrill', verify: verifyMandrill },
])('$name — URL + sorted params', ({ verify }) => {
  const url = 'https://app.example.com/sms/status?source=twilio';
  const params = { MessageSid: 'SM1234', MessageStatus: 'delivered', To: '+15551230000' };
  const secret = 'twilio-auth-token';
  const signingBase = url + 'MessageSidSM1234MessageStatusdeliveredTo+15551230000';
  const header = createHmac('sha1', secret).update(signingBase).digest('base64');

  it.each<{
    name: string;
    url: string;
    params: Record<string, string>;
    secret: string;
    signingBase: string;
  }>([
    {
      name: 'the Twilio status fixture',
      url,
      params,
      secret,
      signingBase,
    },
    {
      name: 'the Twilio fixture with reversed insertion order',
      url,
      params: { To: '+15551230000', MessageStatus: 'delivered', MessageSid: 'SM1234' },
      secret,
      signingBase,
    },
    {
      name: 'the Mandrill events fixture',
      url: 'https://app.example.com/webhooks/mandrill',
      params: { mandrill_events: '[{"event":"open","_id":"abc123"}]' },
      secret: 'mandrill-webhook-key',
      signingBase: 'https://app.example.com/webhooks/mandrillmandrill_events[{"event":"open","_id":"abc123"}]',
    },
    {
      name: 'lexicographic key order including numeric-looking keys',
      url,
      params: { '2': 'two', '10': 'ten', a: 'lower', Z: 'upper' },
      secret,
      signingBase: url + '10ten2twoZupperalower',
    },
    {
      name: 'an exact URL with query order and escaping preserved',
      url: 'https://APP.example.com:443/a/../hook?z=%2f&a=hello+world&a=',
      params: { value: 'a+b & c=%2F' },
      secret,
      signingBase: 'https://APP.example.com:443/a/../hook?z=%2f&a=hello+world&a=valuea+b & c=%2F',
    },
    {
      name: 'UTF-8 keys and values',
      url,
      params: { 'é': 'Sébastien — naïve 🚀', a: '日本語' },
      secret,
      signingBase: url + 'a日本語éSébastien — naïve 🚀',
    },
    { name: 'empty params', url, params: {}, secret, signingBase: url },
    {
      name: 'empty keys and values without separators',
      url,
      params: { z: '', '': 'first', a: '' },
      secret,
      signingBase: url + 'firstaz',
    },
  ])('accepts $name', ({ url, params, secret, signingBase }) => {
    const expectedHeader = createHmac('sha1', secret).update(signingBase).digest('base64');
    expect(verify(url, params, expectedHeader, secret)).toBe(true);
  });

  it('rejects a changed URL, including a changed or omitted query string', () => {
    for (const changedUrl of [
      'http://internal:8080/sms/status?source=twilio',
      'https://app.example.com/sms/status?source=mandrill',
      'https://app.example.com/sms/status',
    ]) {
      expect(verify(changedUrl, params, header, secret)).toBe(false);
    }
  });

  it('rejects a changed parameter', () => {
    expect(verify(url, { ...params, MessageStatus: 'failed' }, header, secret)).toBe(false);
  });

  it('rejects the wrong secret', () => {
    expect(verify(url, params, header, 'wrong-secret')).toBe(false);
  });

  it.each([
    'not-a-signature',
    '!',
    'A'.repeat(27) + '=',
    header.slice(0, -1),
    header + '\n',
    ' ' + header,
    header.toLowerCase(),
  ])('rejects malformed, mismatching or noncanonical header %j', (invalidHeader) => {
    expect(verify(url, params, invalidHeader, secret)).toBe(false);
  });

  it.each([undefined, null, ''])('rejects missing header %j before reading params', (missingHeader) => {
    const unreadableParams = new Proxy({}, {
      ownKeys() { throw new Error('Params must not be enumerated'); },
      get() { throw new Error('Params must not be read'); },
    });
    expect(verify(url, unreadableParams, missingHeader, secret)).toBe(false);
  });

  it.each(['', ' secret with whitespace\n', 'clé🔑'])('uses the entire secret %j', (secret) => {
    const expectedHeader = createHmac('sha1', secret).update(signingBase).digest('base64');
    expect(verify(url, params, expectedHeader, secret)).toBe(true);
  });

  it('uses only own enumerable string keys without mutating params', () => {
    const ownParams: Record<string, string> = Object.create({ inherited: 'ignored' });
    ownParams.visible = 'included';
    Object.defineProperty(ownParams, 'hidden', { value: 'ignored' });
    Object.defineProperty(ownParams, Symbol('symbol'), { value: 'ignored', enumerable: true });
    Object.freeze(ownParams);
    const expectedHeader = createHmac('sha1', secret).update(url + 'visibleincluded').digest('base64');
    expect(verify(url, ownParams, expectedHeader, secret)).toBe(true);
    expect(Object.keys(ownParams)).toEqual(['visible']);
    expect(ownParams.visible).toBe('included');
  });

  it('reads each parameter value once in sorted key order', () => {
    const reads: string[] = [];
    const accessorParams = {
      get b() { reads.push('b'); return 'second'; },
      get a() { reads.push('a'); return 'first'; },
    };
    const expectedHeader = createHmac('sha1', secret).update(url + 'afirstbsecond').digest('base64');
    expect(verify(url, accessorParams, expectedHeader, secret)).toBe(true);
    expect(reads).toEqual(['a', 'b']);
  });
});

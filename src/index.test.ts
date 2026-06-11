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
} from './index.js';

const SECRET = 'whsec_test_4f8a2b';

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

# webhook-verify

Tiny, dependency-free TypeScript verifiers for HMAC-signed webhooks. Every
provider's scheme is the same primitive - a shared secret, an HMAC over bytes
both sides can reconstruct, a constant-time compare - in one of three dialects:

- **Raw body** - HMAC-SHA256 over the exact request bytes. GitHub's
  `X-Hub-Signature-256`, and the right default when signing webhooks between
  your own services.
- **Timestamped** - `t=<unix>,v1=<hex>` over `"<t>.<body>"`, Stripe-style.
  The timestamp plus a tolerance window is the replay defense the other two
  dialects don't have.
- **URL + sorted params** - base64 HMAC-SHA1 over the public webhook URL with
  the POST params appended in key order. Twilio's `X-Twilio-Signature` and
  Mandrill's `X-Mandrill-Signature`.

Runs on Node 18+ (`node:crypto`). No dependencies. Extracted from webhook
receivers I run in production - payment-settlement posts from a card
processor, Mandrill message events, Twilio status callbacks, and
service-to-service webhooks my own apps sign.

## Install

> **Not yet published to npm** - install from GitHub (a `prepare` hook builds it on install):

```bash
npm install github:JacobStephens2/webhook-verify
```

## Raw body (GitHub, your own services)

The body you verify must be the unparsed request bytes. Body-parsing
middleware that re-serializes JSON destroys the signing base - capture the
raw body first.

```ts
import { verifyGitHub } from 'webhook-verify';

app.post('/webhooks/github', express.raw({ type: '*/*' }), (req, res) => {
  if (!verifyGitHub(req.body, req.get('X-Hub-Signature-256'), process.env.WEBHOOK_SECRET!)) {
    return res.status(403).end();
  }
  const event = JSON.parse(req.body.toString('utf8')); // parse only after verifying
  // ...
});
```

For service-to-service webhooks, `signBody`/`verifyBody` are the same scheme
without GitHub's `sha256=` prefix.

## Timestamped (Stripe-style), both directions

```ts
import { signTimestamped, verifyTimestamped } from 'webhook-verify';

// Producer - sign what you send:
const header = signTimestamped(payload, secret, Math.floor(Date.now() / 1000));
await fetch(receiverUrl, {
  method: 'POST',
  headers: { 'Webhook-Signature': header },
  body: payload,
});

// Receiver - default tolerance is 300 seconds either direction:
if (!verifyTimestamped(rawBody, req.get('Webhook-Signature'), secret)) {
  return res.status(403).end();
}
```

Multiple `v1` entries in one header are accepted (sent during key rotation);
any single match passes.

## URL + sorted params (Twilio, Mandrill)

The URL in the signature is the one the **provider** called - the public
`https://` URL, query string included. Behind a reverse proxy your app sees
something else; reconstruct the public URL from configuration, not from the
request.

```ts
import { verifyTwilio, verifyMandrill } from 'webhook-verify';

verifyTwilio(
  'https://app.example.com/sms/status',   // public URL, as configured in Twilio
  req.body,                                // parsed POST params
  req.get('X-Twilio-Signature'),
  process.env.TWILIO_AUTH_TOKEN!,
);

verifyMandrill(
  'https://app.example.com/webhooks/mandrill',
  req.body,
  req.get('X-Mandrill-Signature'),
  process.env.MANDRILL_WEBHOOK_KEY!,
);
```

## API

| Function | Scheme |
|---|---|
| `signBody(rawBody, secret, { algorithm?, encoding? })` | HMAC of the raw bytes (default SHA-256 hex) |
| `verifyBody(rawBody, signature, secret, opts?)` | Verify a raw-body signature |
| `verifyGitHub(rawBody, header, secret)` | GitHub `X-Hub-Signature-256` (`sha256=<hex>`) |
| `signTimestamped(rawBody, secret, timestampSeconds)` | Produce `t=<unix>,v1=<hex>` over `"<t>.<body>"` |
| `verifyTimestamped(rawBody, header, secret, { toleranceSeconds?, nowSeconds? })` | Verify with a replay-tolerance window |
| `verifyTwilio(url, params, header, authToken)` | Twilio `X-Twilio-Signature` |
| `verifyMandrill(url, params, header, webhookKey)` | Mandrill `X-Mandrill-Signature` |
| `safeEqual(a, b)` | Constant-time string compare |

Every verifier returns a boolean and treats a missing or malformed header as
`false` - nothing throws on attacker-controlled input.

## Security notes (read these)

- **Verify the raw bytes.** A signature over the body is a signature over the
  exact bytes on the wire. Parse after verifying, never before.
- **Comparisons are constant-time** (`crypto.timingSafeEqual`). A plain `==`
  against an attacker-supplied signature is a timing oracle.
- **Only the timestamped dialect defends against replay.** A captured
  raw-body or URL+params request verifies forever; if replays matter, add
  event-ID deduplication on top.
- **Fail closed.** An unset secret in your config should reject requests, not
  skip verification. The dangerous failure mode is the receiver that silently
  stops checking.
- **A valid signature authenticates the sender, nothing more.** It doesn't
  authorize the payload's contents, dedupe retries, or replace TLS.

## License

MIT © Jacob Stephens

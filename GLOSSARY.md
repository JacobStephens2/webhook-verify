# Webhook verification

The shared language for authenticating webhook requests.

## Language

**Timestamped signing base**:
The UTF-8 encoding of the existing numeric timestamp representation followed
by a dot, then the unmodified Buffer body or UTF-8-encoded string body.

**URL + sorted params**:
The webhook dialect whose signing base is the public URL exactly as supplied,
including its query string, followed by each own enumerable parameter key and
its string value in default JavaScript lexicographic key order, without
separators. It is authenticated with HMAC-SHA1 and base64 encoding.

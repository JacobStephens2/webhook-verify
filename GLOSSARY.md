# Webhook verification

The shared language for authenticating webhook requests.

## Language

**Timestamped webhook**:
A webhook authenticated by a header carrying a timestamp used to check
freshness and one or more `v1` digest candidates computed from the Timestamped
signing base.

**Timestamped signing base**:
The UTF-8 encoding of the canonical base-10 integer timestamp string followed
by a dot, then the unmodified Buffer body or UTF-8-encoded string body. That
string is `0`, or an optional leading minus followed by a non-zero digit and
digits. A Timestamped webhook `t` value is accepted only when it is that exact
string, which is the timestamp portion. Every other spelling is rejected,
including one that parses as an integer.

**URL + sorted params**:
The webhook dialect whose signing base is the public URL exactly as supplied,
including its query string, followed by each own enumerable parameter key and
its string value in default JavaScript lexicographic key order, without
separators. It is authenticated with HMAC-SHA1 and base64 encoding.

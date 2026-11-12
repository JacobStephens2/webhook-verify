# Webhook verification

The shared language for authenticating webhook requests.

## Language

**Timestamped signing base**:
The UTF-8 encoding of the existing numeric timestamp representation followed
by a dot, then the unmodified Buffer body or UTF-8-encoded string body.

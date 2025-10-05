# Wire Protocol

Envelope:
```json
{
  "type": "USER_HELLO | LIST_REQ | LIST_RES | MSG_DIRECT | USER_DELIVER | ERROR",
  "from": "<uuid>",
  "to": "<uuid-or-null>",
  "ts_ms": 1727270400000,
  "payload": { /* type-specific */ },
  "sig": "<base64url server transport signature or empty>"
}

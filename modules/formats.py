# modules/formats.py
"""
Message envelope & payload helpers for the chat project.

Top-level envelope for every WebSocket frame:
{
  "type": "USER_HELLO|LIST_REQ|LIST_RES|MSG_DIRECT|USER_DELIVER|ERROR",
  "from": "<uuid>",
  "to": "<uuid-or-null>",
  "ts_ms": <int ms since epoch>,
  "payload": { ...type-specific... },
  "sig": "<server-transport-signature b64url or empty>"
}

Rules (clean build):
- Server NEVER decrypts user payloads.
- Binary blobs in JSON (ciphertext, signatures, PEMs) are base64url (URL-safe, no padding).
- Recipients VERIFY content_sig (RSA-PSS SHA-256) over the minimal bundle:
    {"from","to","ts_ms","ciphertext"}  (canonical JSON: sorted keys, compact separators)
- RSA-OAEP(SHA-256) with RSA-4096 for encrypting plaintext to recipient.
- Client keeps a replay guard cache in clean build (dropped in vuln build).
"""

from __future__ import annotations
import time
import json
from typing import Any, Dict, List

# ---------- time ----------
def now_ms() -> int:
    """Current time in milliseconds since epoch."""
    return int(time.time() * 1000)

# ---------- envelope ----------
def envelope(msg_type: str, from_id: str, to_id: str | None, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Standard envelope with fresh timestamp; 'sig' is filled by the server on outgoing frames."""
    return {
        "type": msg_type,
        "from": from_id,
        "to": to_id,
        "ts_ms": now_ms(),
        "payload": payload,
        "sig": ""
    }

# ---------- payload builders ----------
def payload_user_hello(user_pub_b64u: str) -> Dict[str, Any]:
    """Client → Server. Announce the client's public key (base64url-encoded PEM)."""
    return {"user_pub": user_pub_b64u}

def payload_list_req() -> Dict[str, Any]:
    """Client → Server. Ask for online directory."""
    return {}

def payload_list_res(users: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Server → Client. Directory of online users.
    Each item: {"user_id": "<uuid>", "user_pub": "<base64url PEM>"}.
    """
    return {"users": users}

def payload_msg_direct(sender_pub_b64u: str, ciphertext_b64u: str, content_sig_b64u: str) -> Dict[str, Any]:
    """
    Client → Server (MSG_DIRECT) and Server → Client (USER_DELIVER) unchanged.
    Fields:
      - sender_pub   base64url sender PEM (recipient uses it to verify content_sig)
      - ciphertext   base64url RSA-OAEP ciphertext
      - content_sig  base64url RSA-PSS signature over content_sig_material(env)
    """
    return {
        "sender_pub": sender_pub_b64u,
        "ciphertext": ciphertext_b64u,
        "content_sig": content_sig_b64u,
    }

def payload_error(code: str, **extra: Any) -> Dict[str, Any]:
    """Server → Client. Structured error payload."""
    out = {"code": code}
    out.update(extra)
    return out

# ---------- signing material ----------
def content_sig_material(env_like: Dict[str, Any]) -> bytes:
    """
    Canonical JSON bytes of the minimal bundle the sender signs:
      {"from","to","ts_ms","ciphertext"}
    'ciphertext' is taken from env_like["payload"]["ciphertext"] exactly (base64url string).
    Canonicalization = sorted keys, compact separators.
    """
    material = {
        "from": env_like["from"],
        "to": env_like["to"],
        "ts_ms": env_like["ts_ms"],
        "ciphertext": env_like["payload"]["ciphertext"],
    }
    return json.dumps(material, separators=(",", ":"), sort_keys=True).encode("utf-8")

# ---------- optional quick validator ----------
_REQUIRED_ENVELOPE_KEYS = ("type", "from", "to", "ts_ms", "payload", "sig")
def validate_envelope_shape(obj: Dict[str, Any]) -> None:
    for k in _REQUIRED_ENVELOPE_KEYS:
        if k not in obj:
            raise ValueError(f"envelope missing key: {k}")
    if not isinstance(obj["payload"], dict):
        raise ValueError("payload must be a dict")
    if not isinstance(obj["ts_ms"], int):
        raise ValueError("ts_ms must be int (ms since epoch)")

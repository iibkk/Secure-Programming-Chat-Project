# modules/formats.py
"""
Message envelope and payload helpers.

Envelope (one JSON per WebSocket frame):
{ "type": str, "from": str, "to": str|null, "ts_ms": int, "payload": dict, "sig": str }

Binary fields inside JSON are base64url (no padding).
"""
from __future__ import annotations
import time
from typing import Dict, Any
from .crypto_rsa import canon  # used by content_sig_material

def now_ms() -> int:
    return int(time.time() * 1000)

def envelope(msg_type: str, from_id: str, to_id: str | None, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": msg_type,
        "from": from_id,
        "to": to_id,
        "ts_ms": now_ms(),
        "payload": payload,
        "sig": ""  # server transport signature filled in by server.py
    }

# ---- payload builders ----

def payload_user_hello(user_pub_b64u: str) -> Dict[str, Any]:
    return {"user_pub": user_pub_b64u}

def payload_list_req() -> Dict[str, Any]:
    return {}

def payload_list_res(users: list[dict]) -> Dict[str, Any]:
    # each item: {"user_id": <uuid>, "user_pub": <b64u PEM>}
    return {"users": users}

def payload_msg_direct(sender_pub_b64u: str, ciphertext_b64u: str, content_sig_b64u: str) -> Dict[str, Any]:
    return {"sender_pub": sender_pub_b64u, "ciphertext": ciphertext_b64u, "content_sig": content_sig_b64u}

# What the sender signs for content_sig (canonical JSON bytes)
def content_sig_material(env_like: Dict[str, Any]) -> bytes:
    material = {
        "from": env_like["from"],
        "to": env_like["to"],
        "ts_ms": env_like["ts_ms"],
        "ciphertext": env_like["payload"]["ciphertext"],
    }
    return canon(material)

from __future__ import annotations

import json, base64, uuid
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


# Base64url
def b64u_encode(b: bytes) -> str:
    """URL-safe base64 without = padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64u_decode(s: str) -> bytes:
    """URL-safe base64 decoder tolerant of missing padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

# Canonical JSON (sorted keys, compact) for signing
def canon(obj) -> bytes:
    """Deterministic JSON encoding for signatures/hashes."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

# RSA key management (on-disk identity)
def ensure_rsa_keypair(dirpath: Path, prefix: str) -> Tuple[rsa.RSAPrivateKey, bytes]:
    """
    Ensure a strong (4096-bit) RSA keypair exists at the given location.
    Returns (private_key, public_pem_bytes).
    """
    dirpath.mkdir(parents=True, exist_ok=True)
    priv_p = dirpath / f"{prefix}_priv.pem"
    pub_p  = dirpath / f"{prefix}_pub.pem"
    if not priv_p.exists():
        priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        priv_p.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
        pub_p.write_bytes(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    priv = serialization.load_pem_private_key(priv_p.read_bytes(), password=None)
    pub_pem = pub_p.read_bytes()
    return priv, pub_pem

def generate_local_keypair(dirpath: Path, prefix: str, *, weak: bool | None = None):
    """
    Convenience generator that respects the vulnerable weak-key toggle.
    If weak is None, uses VULN_WEAK_KEYS; weak=True => 1024-bit, else 4096-bit.
    """
    dirpath.mkdir(parents=True, exist_ok=True)
    priv_p = dirpath / f"{prefix}_priv.pem"
    pub_p  = dirpath / f"{prefix}_pub.pem"

    # decide bit length
    bits = MIN_RSA_BITS_VULN if (weak if weak is not None else VULN_WEAK_KEYS) else MIN_RSA_BITS_CLEAN

    if not priv_p.exists():
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        priv_p.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
        pub_p.write_bytes(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    priv = serialization.load_pem_private_key(priv_p.read_bytes(), password=None)
    return priv, pub_p.read_bytes()

def load_pub_from_b64u_pem(b64u_pem: str):
    pem = b64u_decode(b64u_pem)
    return serialization.load_pem_public_key(pem)

def public_pem_to_b64u(pub) -> str:
    """Public key PEM → base64url string (no padding)."""
    pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64u_encode(pem)

def new_uuid() -> str:
    return str(uuid.uuid4())

# RSA OAEP (SHA-256) and PSS (SHA-256)

def rsa_encrypt_oaep(peer_pub, plaintext: bytes) -> bytes:
    """Encrypt with RSAES-OAEP (SHA-256)."""
    return peer_pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt_oaep(priv, ciphertext: bytes) -> bytes:
    """Decrypt with RSAES-OAEP (SHA-256)."""
    return priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

def rsa_sign_pss(priv, data: bytes) -> bytes:
    """Sign with RSASSA-PSS (SHA-256)."""
    return priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_verify_pss(pub, data: bytes, sig: bytes) -> bool:
    """Verify RSASSA-PSS (SHA-256) signature."""
    try:
        pub.verify(
            sig, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# RSA-4096 with SHA-256 OAEP leaves ~446 bytes of plaintext capacity
RSA_OAEP_SHA256_MAX_PT = 512 - (2*32 + 2)  # bytes  (k - 2*hLen - 2 for k=512, hLen=32)

def oaep_plaintext_limit_bytes(pub) -> int:
    """
    Per-key OAEP limit:
      max = k - 2*hLen - 2
      4096-bit -> 512 - 64 - 2 = 446
      1024-bit -> 128 - 64 - 2 = 62
    """
    k = pub.key_size // 8
    return k - (2*32 + 2)


# Vulnerable build toggle (weak keys) and key-size policy
# CLEAN build default: keep False. VULN build will set this True.
VULN_WEAK_KEYS: bool = False

MIN_RSA_BITS_CLEAN = 4096
MIN_RSA_BITS_VULN  = 1024

def is_valid_pubkey_len(pub) -> bool:
    """
    Clean build: require >= 4096-bit.
    Vuln build: allow >= 1024-bit.
    """
    try:
        bits = pub.key_size
    except Exception:
        return False
    min_bits = MIN_RSA_BITS_VULN if VULN_WEAK_KEYS else MIN_RSA_BITS_CLEAN
    return bits >= min_bits


# Content signature helpers (PSS over canonical JSON)
def content_sig_make(priv, obj) -> str:
    """
    Return base64url(signature) where signature = PSS-SHA256( canon(obj) ).
    Intended 'obj' shape: {from, to, ts_ms, ciphertext}
    """
    sig = rsa_sign_pss(priv, canon(obj))
    return b64u_encode(sig)

def content_sig_verify(pub, obj, sig_b64u: str) -> bool:
    try:
        sig = b64u_decode(sig_b64u)
    except Exception:
        return False
    return rsa_verify_pss(pub, canon(obj), sig)


# Self-test (run: python -m modules.crypto_rsa)
if __name__ == "__main__":
    from tempfile import TemporaryDirectory

    print("[crypto_rsa] self-test start")

    # Strong-key path (clean)
    with TemporaryDirectory() as td:
        priv, pub_pem = ensure_rsa_keypair(Path(td), "id")
        pub = serialization.load_pem_public_key(pub_pem)

        # OAEP limit check
        assert oaep_plaintext_limit_bytes(pub) == RSA_OAEP_SHA256_MAX_PT

        # enc/dec
        ct = rsa_encrypt_oaep(pub, b"hello")
        assert rsa_decrypt_oaep(priv, ct) == b"hello"

        # content sig
        material = {"from": "a", "to": "b", "ts_ms": 123, "ciphertext": "deadbeef"}
        sig_b64u = content_sig_make(priv, material)
        assert content_sig_verify(pub, material, sig_b64u) is True

        # b64url round trip for pub
        b64u_pub = public_pem_to_b64u(pub)
        pub2 = load_pub_from_b64u_pem(b64u_pub)
        assert getattr(pub2, "key_size", None) == getattr(pub, "key_size", None)

        # key-size policy (clean)
        assert is_valid_pubkey_len(pub) is True

    # Weak-key path (vuln toggle demo)
    with TemporaryDirectory() as td:
        VULN_WEAK_KEYS = True
        priv_w, pub_pem_w = generate_local_keypair(Path(td), "id", weak=None)  # picks 1024 now
        pub_w = serialization.load_pem_public_key(pub_pem_w)
        # 1024-bit allowed in vuln mode
        assert is_valid_pubkey_len(pub_w) is True
        # OAEP limit should be 62
        assert oaep_plaintext_limit_bytes(pub_w) == 62

        # sign/verify still works
        sig_b64u_w = content_sig_make(priv_w, {"x": 1})
        assert content_sig_verify(pub_w, {"x": 1}, sig_b64u_w) is True

    print("[crypto_rsa] self-test OK")
    
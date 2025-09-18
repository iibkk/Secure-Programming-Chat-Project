# modules/crypto_rsa.py
from __future__ import annotations
import json, base64, uuid
from pathlib import Path
from typing import Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# ===== base64url (no padding) =====
def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64u_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

# ===== canonical JSON for signing =====
def canon(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

# ===== RSA key management =====
def ensure_rsa_keypair(dirpath: Path, prefix: str) -> Tuple[rsa.RSAPrivateKey, bytes]:
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

def load_pub_from_b64u_pem(b64u_pem: str):
    pem = b64u_decode(b64u_pem)
    return serialization.load_pem_public_key(pem)

def new_uuid() -> str:
    return str(uuid.uuid4())

# ===== RSA OAEP / PSS =====
def rsa_encrypt_oaep(peer_pub, plaintext: bytes) -> bytes:
    return peer_pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt_oaep(priv, ciphertext: bytes) -> bytes:
    return priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

def rsa_sign_pss(priv, data: bytes) -> bytes:
    return priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_verify_pss(pub, data: bytes, sig: bytes) -> bool:
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
RSA_OAEP_SHA256_MAX_PT = 512 - (2*32 + 2)  # bytes

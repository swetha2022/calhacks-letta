from __future__ import annotations
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, json
import binascii
from base64 import b64encode, b64decode

##PUBLIC KEY ENCRYPTION WITH RSA OAEP AND SIGNING WITH RSA PSS##
# -------- helpers --------
SCHEME_ID = "RSA-OAEP(SHA-256)+RSA-PSS(SHA-256)"
SIG_CTX = b"letta-signed-rsa-oaep-v1"

def _b64(x: bytes) -> str: return b64encode(x).decode("ascii")
def _b64d(s: str) -> bytes: return b64decode(s.encode("ascii"))

def _sha256(x: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(x)
    return h.finalize()

def _to_sign(aad_hash: bytes, ct: bytes) -> bytes:
    # Minimal, canonical layout for the signed message
    return b"|".join([SIG_CTX, SCHEME_ID.encode(), aad_hash, ct])

def _load_pub(pem: bytes | str):
    if isinstance(pem, str): pem = pem.encode()
    return serialization.load_pem_public_key(pem)

def _load_priv(pem: bytes | str, password: Optional[bytes] = None):
    if isinstance(pem, str): pem = pem.encode()
    return serialization.load_pem_private_key(pem, password=password)

# -------- API --------
def generate_rsa_keypair(
    key_size: int = 2048,
    password: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Generate an RSA keypair suitable for OAEP+PSS.

    Args:
        key_size: modulus size in bits (2048, 3072, 4096).
        password: optional password (bytes) to encrypt the private key PEM.

    Returns:
        (private_pem_bytes, public_pem_bytes)
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()

    if password:
        encryption_alg = serialization.BestAvailableEncryption(password)
    else:
        encryption_alg = serialization.NoEncryption()

    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg,
    )

    public_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem

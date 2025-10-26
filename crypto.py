from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, json
import binascii
from base64 import b64encode, b64decode

from dotenv import load_dotenv #load env file
load_dotenv()

def derive_key(label: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derive a single key (e.g., encryption or authentication) from the master key using HKDF.

    Args:
        label: Either "enc" or "auth" — determines the key domain.
        salt:  A per-memory or per-session salt (e.g., memory ID bytes).
        length: Desired key length in bytes (default 32).
    """
    # Load master key from environment (expected as hex string)
    master_hex = os.getenv("MASTER_PRIVATE_KEY")
    if not master_hex:
        raise ValueError("Missing environment variable: MASTER_PRIVATE_KEY")

    try:
        master_key = binascii.unhexlify(master_hex)
    except Exception as e:
        raise ValueError("MASTER_PRIVATE_KEY must be a valid hex string") from e

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=f"letta/agent-memory/v1/{label}".encode("utf-8"),  # domain separation
    )
    derived_key = hkdf.derive(master_key)
    return derived_key

def encrypt_value(label: str, plaintext: str, aad: bytes | None = None) -> str:
    """
    Encrypt a UTF-8 string using AES-GCM with a per-entry random salt and nonce.
    Returns a JSON string containing salt, nonce, and ciphertext (all base64).

    Args:
        label: Domain label for key derivation (e.g., "enc").
        plaintext: The string to encrypt.
        aad: Optional associated data to bind into the AEAD (not stored).
    """
    if not isinstance(plaintext, str):
        raise TypeError("encrypt_value expects plaintext as str")
    # Per-memory salt (for HKDF) and nonce (for AES-GCM)
    salt = os.urandom(16)
    key = derive_key(label, salt=salt, length=32)  # 256-bit key
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM standard nonce size
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

    bundle = {
        "alg": "AESGCM",
        "kdf": "HKDF-SHA256",
        "label": label,
        "salt_b64": b64encode(salt).decode("ascii"),
        "nonce_b64": b64encode(nonce).decode("ascii"),
        "ct_b64": b64encode(ct).decode("ascii"),
        # NOTE: AAD is not stored; if you use AAD, the decryptor must supply the same bytes.
    }
    return json.dumps(bundle, separators=(",", ":"))

def decrypt_value(enc_bundle_json: str, aad: bytes | None = None) -> str:
    """
    Decrypt a JSON bundle produced by encrypt_value and return the original UTF-8 string.

    Args:
        enc_bundle_json: JSON string with fields salt_b64, nonce_b64, ct_b64, label, alg, kdf.
        aad: Optional associated data; must match what was used during encryption.
    """
    try:
        bundle = json.loads(enc_bundle_json)
        if bundle.get("alg") != "AESGCM" or bundle.get("kdf") != "HKDF-SHA256":
            raise ValueError("Unsupported alg/kdf in bundle")

        label = bundle["label"]
        salt = b64decode(bundle["salt_b64"])
        nonce = b64decode(bundle["nonce_b64"])
        ct = b64decode(bundle["ct_b64"])
    except (KeyError, ValueError, binascii.Error, json.JSONDecodeError) as e:
        raise ValueError("Invalid encryption bundle") from e

    key = derive_key(label, salt=salt, length=32)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt.decode("utf-8")
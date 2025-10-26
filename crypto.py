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

# from dotenv import load_dotenv #load env file
# load_dotenv()

# def derive_key(label: str, salt: bytes, length: int = 32) -> bytes:
#     """
#     Derive a single key (e.g., encryption or authentication) from the master key using HKDF.

#     Args:
#         label: Either "enc" or "auth" — determines the key domain.
#         salt:  A per-memory or per-session salt (e.g., memory ID bytes).
#         length: Desired key length in bytes (default 32).
#     """
#     # Load master key from environment (expected as hex string)
#     master_hex = os.getenv("MASTER_PRIVATE_KEY")
#     if not master_hex:
#         raise ValueError("Missing environment variable: MASTER_PRIVATE_KEY")

#     try:
#         master_key = binascii.unhexlify(master_hex)
#     except Exception as e:
#         raise ValueError("MASTER_PRIVATE_KEY must be a valid hex string") from e

#     hkdf = HKDF(
#         algorithm=hashes.SHA256(),
#         length=length,
#         salt=salt,
#         info=f"letta/agent-memory/v1/{label}".encode("utf-8"),  # domain separation
#     )
#     derived_key = hkdf.derive(master_key)
#     return derived_key

# def encrypt_value(label: str, plaintext: str, aad: bytes | None = None) -> str:
#     """
#     Encrypt a UTF-8 string using AES-GCM with a per-entry random salt and nonce.
#     Returns a JSON string containing salt, nonce, and ciphertext (all base64).

#     Args:
#         label: Domain label for key derivation (e.g., "enc").
#         plaintext: The string to encrypt.
#         aad: Optional associated data to bind into the AEAD (not stored).
#     """
#     if not isinstance(plaintext, str):
#         raise TypeError("encrypt_value expects plaintext as str")
#     # Per-memory salt (for HKDF) and nonce (for AES-GCM)
#     salt = os.urandom(16)
#     key = derive_key(label, salt=salt, length=32)  # 256-bit key
#     aesgcm = AESGCM(key)
#     nonce = os.urandom(12)  # AES-GCM standard nonce size
#     ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

#     bundle = {
#         "alg": "AESGCM",
#         "kdf": "HKDF-SHA256",
#         "label": label,
#         "salt_b64": b64encode(salt).decode("ascii"),
#         "nonce_b64": b64encode(nonce).decode("ascii"),
#         "ct_b64": b64encode(ct).decode("ascii"),
#         # NOTE: AAD is not stored; if you use AAD, the decryptor must supply the same bytes.
#     }
#     return json.dumps(bundle, separators=(",", ":")), key

# def decrypt_value(enc_bundle_json: str, key: Optional[bytes], aad: bytes | None = None) -> str:
#     """
#     Decrypt a JSON bundle produced by encrypt_value and return the original UTF-8 string.

# #     Args:
# #         enc_bundle_json: JSON string with fields salt_b64, nonce_b64, ct_b64, label, alg, kdf.
# #         aad: Optional associated data; must match what was used during encryption.
# #     """
#     try:
#         bundle = json.loads(enc_bundle_json)
#         if bundle.get("alg") != "AESGCM" or bundle.get("kdf") != "HKDF-SHA256":
#             raise ValueError("Unsupported alg/kdf in bundle")

#         label = bundle["label"]
#         salt = b64decode(bundle["salt_b64"])
#         nonce = b64decode(bundle["nonce_b64"])
#         ct = b64decode(bundle["ct_b64"])
#     except (KeyError, ValueError, binascii.Error, json.JSONDecodeError) as e:
#         raise ValueError("Invalid encryption bundle") from e

#     if key:
#         key = key
#     else:
#         key = derive_key(label, salt=salt, length=32)
#     aesgcm = AESGCM(key)
#     pt = aesgcm.decrypt(nonce, ct, aad)
#     return pt.decode("utf-8")


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

# def rsa_oaep_pss_encrypt(
#     plaintext: str,
#     *,
#     recipient_rsa_pub_pem: bytes | str,
#     sender_rsapss_priv_pem: bytes | str,
#     sender_priv_password: Optional[bytes] = None,
#     aad: Optional[bytes] = None,
# ) -> str:
#     """
#     Encrypt with RSA-OAEP(SHA-256) and sign the resulting ciphertext using RSA-PSS(SHA-256).
#     AAD (if provided) is *not* stored; its SHA-256 is included in the signature and also used
#     as the OAEP label (binding AAD at both layers).
#     Returns a JSON bundle with {scheme, ct_b64, sig_b64, aad_sha256_b64}.
#     """
#     if not isinstance(plaintext, str):
#         raise TypeError("plaintext must be str")

#     pub = _load_pub(recipient_rsa_pub_pem)
#     signer = _load_priv(sender_rsapss_priv_pem, password=sender_priv_password)

#     aad_bytes = aad if aad is not None else b""
#     aad_hash = _sha256(aad_bytes)

#     # RSA-OAEP encrypt (bind AAD via label)
#     ct = pub.encrypt(
#         plaintext.encode("utf-8"),
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=aad_bytes if aad_bytes else None,
#         ),
#     )

#     # RSA-PSS signature over (scheme || aad_hash || ct)
#     to_sign = _to_sign(aad_hash, ct)
#     sig = signer.sign(
#         to_sign,
#         padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
#         hashes.SHA256(),
#     )

#     bundle = {
#         "scheme": SCHEME_ID,
#         "ct_b64": _b64(ct),
#         "sig_b64": _b64(sig),
#         "aad_sha256_b64": _b64(aad_hash),
#     }
#     return json.dumps(bundle, separators=(",", ":"))

# def rsa_oaep_pss_decrypt(
#     bundle_json: str,
#     *,
#     recipient_rsa_priv_pem: bytes | str,
#     sender_rsapss_pub_pem: bytes | str,
#     recipient_priv_password: Optional[bytes] = None,
#     aad: Optional[bytes] = None,
# ) -> str:
#     """
#     Verify RSA-PSS signature first, then RSA-OAEP decrypt.
#     Requires the same AAD bytes used at encryption (if any).
#     """
#     try:
#         b = json.loads(bundle_json)
#         if b.get("scheme") != SCHEME_ID:
#             raise ValueError("Unsupported or mismatched scheme")
#         ct = _b64d(b["ct_b64"])
#         sig = _b64d(b["sig_b64"])
#         aad_hash_stored = _b64d(b["aad_sha256_b64"])
#     except (KeyError, ValueError, binascii.Error, json.JSONDecodeError) as e:
#         raise ValueError("Invalid RSA bundle") from e

#     aad_bytes = aad if aad is not None else b""
#     aad_hash = _sha256(aad_bytes)
#     if aad_hash != aad_hash_stored:
#         raise ValueError("AAD mismatch")

#     verifier = _load_pub(sender_rsapss_pub_pem)
#     to_verify = _to_sign(aad_hash, ct)
#     try:
#         verifier.verify(
#             sig,
#             to_verify,
#             padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
#             hashes.SHA256(),
#         )
#     except InvalidSignature as e:
#         raise ValueError("Invalid signature") from e

#     priv = _load_priv(recipient_rsa_priv_pem, password=recipient_priv_password)
#     pt = priv.decrypt(
#         ct,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=aad_bytes if aad_bytes else None,
#         ),
#     )
#     return pt.decode("utf-8")

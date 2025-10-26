from __future__ import annotations
import os, json

from dotenv import load_dotenv #load env file
load_dotenv()

from letta_client import Letta

from typing import Optional

# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.asymmetric import padding, rsa
# from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
# from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
from base64 import b64encode, b64decode


def get_client() -> Letta:
    token = os.getenv("LETTA_API_KEY")
    if not token or not token.strip():
        raise ValueError("LETTA_API_KEY missing/empty (check your .env and that load_dotenv() ran)")
    token = token.strip().strip('"').strip("'")  # guard against pasted quotes/spaces
    base_url = os.getenv("LETTA_API_BASE_URL")   # set if self-hosting; omit for cloud
    return Letta(token=token, base_url=base_url) if base_url else Letta(token=token)

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

def decrypt_value(enc_bundle_json: str, key: Optional[bytes], aad: bytes | None = None) -> str:
    """
    Decrypt a JSON bundle produced by encrypt_value and return the original UTF-8 string.

#     Args:
#         enc_bundle_json: JSON string with fields salt_b64, nonce_b64, ct_b64, label, alg, kdf.
#         aad: Optional associated data; must match what was used during encryption.
#     """
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

    if key:
        key = key
    else:
        key = derive_key(label, salt=salt, length=32)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt.decode("utf-8")

from typing import Optional
import base64, json

def read_memory(
    info_block_id: str,
    *,
    key_b64: Optional[str] = None,
    aad_b64: Optional[str] = None,
) -> str:
    """
    Retrieve and decrypt plaintext data given an *info block ID* (block-<uuid4>).

    Args:
        info_block_id: The ID of the info block that references the encrypted content block.
        key_b64: Optional base64-encoded symmetric key to use for decryption.
        aad_b64: Optional base64-encoded AAD that must match what was used during encryption.

    Returns:
        Decrypted plaintext contents of the referenced content block.
    """
    if not isinstance(info_block_id, str):
        raise ValueError(f"Invalid info_block_id format: {info_block_id!r}")

    client = get_client()

    # 1) Retrieve the info block and get its encrypted value
    info_block = client.blocks.retrieve(info_block_id)
    enc_info = info_block.get("value") if isinstance(info_block, dict) else getattr(info_block, "value", None)
    if enc_info is None:
        raise ValueError(f"Info block {info_block_id} has no 'value' to decrypt")

    # 2) Decode inputs
    key: Optional[bytes] = base64.b64decode(key_b64) if key_b64 else None
    aad: Optional[bytes] = base64.b64decode(aad_b64) if aad_b64 else None

    # 3) Decrypt info → parse JSON → extract content block id
    info_plain = decrypt_value(enc_info, key=key, aad=aad)
    try:
        info_obj = json.loads(info_plain)
    except json.JSONDecodeError as e:
        raise ValueError(f"Decrypted info for {info_block_id} is not valid JSON") from e

    content_block_id = info_obj.get("Memory Block ID")
    if not isinstance(content_block_id, str):
        raise ValueError(f"Info object missing valid 'Memory Block ID' (got: {content_block_id!r})")

    # 4) Retrieve & decrypt the content block
    content_block = client.blocks.retrieve(content_block_id)
    enc_content = content_block.get("value") if isinstance(content_block, dict) else getattr(content_block, "value", None)
    if enc_content is None:
        raise ValueError(f"Content block {content_block_id} has no 'value' to decrypt")

    return decrypt_value(enc_content, key=key, aad=aad)


# def read_memory(
#     info_block_or_id: str,
#     key_b64: Optional[str] = None,
#     aad_b64: Optional[str] = None,
# ) -> str:
#     """
#     Retrieve and decrypt plaintext data from a stored memory block using its info block.

#     Args:
#         info_block_or_id (str): The ID of an info block that references an encrypted content block.
#         key_b64 (str | None): Optional base64-encoded symmetric key. If provided, this key is used
#             directly for decryption. Defaults to None.
#         aad_b64 (str | None): Optional base64-encoded Additional Authenticated Data (AAD) that must
#             match what was used during encryption. Defaults to None.

#     Returns:
#         str: The decrypted plaintext contents of the referenced memory block.

#     Raises:
#         ValueError: If required fields are missing or JSON is malformed.
#         RuntimeError: If decryption fails (bad key, corrupted ciphertext, or AAD mismatch).
#     """
#     client = get_client()

#     # Load info block
#     info_block = client.blocks.retrieve(info_block_or_id)
#     enc_info = info_block.get("value") if isinstance(info_block, dict) else getattr(info_block, "value", None)
#     if enc_info is None:
#         raise ValueError("Info block has no 'value' to decrypt")

#     # Decode inputs
#     key: bytes | None = base64.b64decode(key_b64) if key_b64 else None
#     aad: bytes | None = base64.b64decode(aad_b64) if aad_b64 else None

#     # Decrypt info → get content block id
#     info_plain = decrypt_value(enc_info, key=key, aad=aad)
#     info_obj = json.loads(info_plain)
#     content_block_id = info_obj["Memory Block ID"]

#     # Decrypt content
#     content_block = client.blocks.retrieve(content_block_id)
#     enc_content = content_block.get("value") if isinstance(content_block, dict) else getattr(content_block, "value", None)
#     if enc_content is None:
#         raise ValueError("Content block has no 'value' to decrypt")

#     return decrypt_value(enc_content, key=key, aad=aad)


# # def read_memory(info_block_or_id, key = Optional[bytes], aad: bytes | None = None) -> str:
# #     """
# #     Retrieve and decrypt plaintext data from a stored memory block using its associated info block.

# #     Args:
# #         info_block_or_id (str | dict | object): The info block (or its ID) that references
# #             the encrypted content block. Can be:
# #                 - A string block ID (e.g., "block-abc123...")
# #                 - A dict containing a "value" field
# #                 - An SDK block object with a `.value` attribute
# #         key (bytes | None): Optional symmetric key used to decrypt the memory contents.
# #             If provided, it overrides any key derivation logic and is passed directly to
# #             `decrypt_value()`. Defaults to None.
# #         aad (bytes | None): Optional Additional Authenticated Data (AAD) used for
# #             AES-GCM decryption. Must match the AAD used at encryption time, or left None
# #             if no AAD was used. Defaults to None.

# #     Returns:
# #         str: The decrypted plaintext contents of the referenced memory block.

# #     Raises:
# #         ValueError: If the info block or content block lacks a "value" field, the decrypted
# #             content is not valid JSON, or the JSON is missing the expected
# #             `"Memory Block ID"` key.
# #         RuntimeError: If decryption fails due to an invalid key, corrupted ciphertext,
# #             or mismatched AAD.

# #     Description:
# #         This function performs a two-stage decryption process for Letta memory storage:
# #             1. Decrypt the provided info block to extract the ID of the referenced
# #                content block (from the stored JSON metadata).
# #             2. Retrieve that content block and decrypt its encrypted value to return
# #                the original plaintext string.

# #         If `key` is supplied, it is used directly for both decryptions.
# #         If omitted, the default `decrypt_value()` implementation will derive or load
# #         the appropriate key internally.

# #     Example:
# #         >>> plaintext = read_memory("block-1234abcd")
# #         >>> print(plaintext)
# #         "My stored memory text"
# #     """
# #     client = get_client()

# #     # Normalize: accept id, dict, or SDK object for the info block
# #     if isinstance(info_block_or_id, str):
# #         info_block = client.blocks.retrieve(info_block_or_id)
# #     else:
# #         info_block = info_block_or_id

# #     # 1) Decrypt the info block's value (must be the encrypted bundle string)
# #     enc_info = (
# #         info_block.get("value") if isinstance(info_block, dict)
# #         else getattr(info_block, "value", None)
# #     )
# #     if enc_info is None:
# #         raise ValueError("Info block has no 'value' to decrypt")
# #     if key:
# #         info_plain = decrypt_value(enc_info, key=key, aad=aad)
# #     else:
# #         info_plain = decrypt_value(enc_info, aad=aad)  # returns a plaintext string

# #     # 2) Parse the JSON you stored in create_info_block
# #     try:
# #         info_obj = json.loads(info_plain)
# #     except json.JSONDecodeError:
# #         raise ValueError("Info block plaintext is not JSON; expected keys like 'Memory Block ID'")

# #     content_block_id = info_obj["Memory Block ID"]

# #     # 3) Fetch content block and decrypt its value
# #     content_block = client.blocks.retrieve(content_block_id)
# #     enc_content = (
# #         content_block.get("value") if isinstance(content_block, dict)
# #         else getattr(content_block, "value", None)
# #     )
# #     if enc_content is None:
# #         raise ValueError("Content block has no 'value' to decrypt")

# #     if key:
# #         content_plain = decrypt_value(enc_content, key=key, aad=aad)  # plaintext string of your memory
# #     else:
# #         content_plain = decrypt_value(enc_content, aad=aad)
# #     return content_plain
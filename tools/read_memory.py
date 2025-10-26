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

def read_memory(info_block_or_id:str) -> str:
    """
    Retrieve and decrypt plaintext data from a stored memory block using its info block.

    Args:
        info_block_or_id (str): The ID of an info block (or a serialized info block object)
            that contains a reference to an encrypted memory block. This identifies which
            piece of memory data to read and decrypt.

    Returns:
        str: The decrypted plaintext contents of the referenced memory block.

    Raises:
        ValueError: If the provided info block has no 'value' field or if its decrypted
            content cannot be parsed as valid JSON containing a 'Memory Block ID'.

    Description:
        This tool accepts an info block (or its ID) previously created by
        `create_info_block()` and stored in Letta. It first decrypts the info block
        to obtain the JSON metadata that includes the associated memory block ID.
        It then retrieves that memory block, decrypts its stored ciphertext,
        and returns the original plaintext string value.

    Example:
        >>> plaintext = read_memory("block-1234abcd")
        >>> print(plaintext)
        'My stored memory text'
    """
    # from tooling import get_client
    # from crypto import decrypt_value
    client = get_client()

    # Normalize: accept id, dict, or SDK object for the info block
    if isinstance(info_block_or_id, str):
        info_block = client.blocks.retrieve(info_block_or_id)
    else:
        info_block = info_block_or_id

    # 1) Decrypt the info block's value (must be the encrypted bundle string)
    enc_info = (
        info_block.get("value") if isinstance(info_block, dict)
        else getattr(info_block, "value", None)
    )
    if enc_info is None:
        raise ValueError("Info block has no 'value' to decrypt")
    info_plain = decrypt_value(enc_info)  # returns a plaintext string

    # 2) Parse the JSON you stored in create_info_block
    try:
        info_obj = json.loads(info_plain)
    except json.JSONDecodeError:
        raise ValueError("Info block plaintext is not JSON; expected keys like 'Memory Block ID'")

    content_block_id = info_obj["Memory Block ID"]

    # 3) Fetch content block and decrypt its value
    content_block = client.blocks.retrieve(content_block_id)
    enc_content = (
        content_block.get("value") if isinstance(content_block, dict)
        else getattr(content_block, "value", None)
    )
    if enc_content is None:
        raise ValueError("Content block has no 'value' to decrypt")

    content_plain = decrypt_value(enc_content)  # plaintext string of your memory
    return content_plain
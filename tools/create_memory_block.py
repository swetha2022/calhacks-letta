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
    return json.dumps(bundle, separators=(",", ":")), key

def create_info_block(memory_block_id, label, description):
    """
    create an info block that contains a key, location to memory block, and the label. Return info block.
    """
    client = get_client()
    value = f'{{"Memory Block ID": "{memory_block_id}", "Label": "{label}", "Key": "{derive_key(label, salt=memory_block_id.encode(), length=32).hex()}"}}'
    encrypted_value, key = encrypt_value("enc", value)
    info_block = client.blocks.create(
        label=f"info-{label}",
        description=description,
        value=encrypted_value,
    )
    return info_block, key

def get_block_label(block_id: str) -> str | None:
    """Return the label of a block given its block_id."""
    client = get_client()
    block = client.blocks.retrieve(block_id)
    # block is usually a dict-like object
    return block.label


def createOwnerIdentity(agentid, memoryid): 
    """each memory is associated with an owner and the properties are the sharer's id and their info_data block id plus key to decrypt
    """
    client = get_client()
    identity = client.identities.create(
        agent_ids=[agentid], #owner
        identifier_key=str(memoryid), #memory block
        name=get_block_label(memoryid), 
        identity_type="other",
        properties=[] #sharer info to be filled when shared later
    )
    return identity

def create_memory_block(agentid: str, label: str, value: str, description: str) -> dict:
    """
    Create a memory block and attach a corresponding info block to the given agent.

    Args:
        agentid (str): The ID of the agent that will own/attach the blocks.
        label (str): Label to assign to the new memory block.
        value (str): Plaintext content to encrypt and store in the memory block.
        description (str): Human-readable description for the memory block.

    Returns:
        dict: A JSON-serializable summary containing the created block IDs.
            Example:
            {
                "memory_block_id": "block-...",
                "info_block_id": "block-..."
            }
    """
    client = get_client()

    # Encrypt plaintext before storing
    encrypted_value, _ = encrypt_value("enc", value)

    # Create the memory block
    memory_block = client.blocks.create(
        label=label,
        description=description,
        value=encrypted_value,
    )

    # Create the info block that points to the memory block
    info_block, _ = create_info_block(
        memory_block.id,
        label=label,
        description="Pointer to memory block"
    )

    # Attach the info block to the agent
    client.agents.blocks.attach(agent_id=agentid, block_id=info_block.id)

    # Update owner identity mapping (if your helper does that)
    createOwnerIdentity(agentid, memory_block.id)

    # ✅ Return JSON-serializable data (avoid returning SDK objects)
    return {
        "memory_block_id": getattr(memory_block, "id", None),
        "info_block_id": getattr(info_block, "id", None),
    }



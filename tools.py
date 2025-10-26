from letta import tool
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
import binascii

@tool
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


@tool
def create_memory_block(agentid, label: str, value: str, description: str):
    """
    create a memory block mapped to an info block that contains a key, location to memory block, and the label. Return info block.
    """
    #TODO CREATE BLOCK FUNCTION LATER
    memory_block = create_block(
        label=label,
        description=description,
        value=value,
    )
    info_block = create_info_block(memory_block.id, label, description)
    #attach info_block to agent and return info_block.id
    attack_block_to_agent(agentid, info_block.id)
    return info_block.id

def create_info_block(memory_block_id, label, description):
    """
    create an info block that contains a key, location to memory block, and the label. Return info block.
    """
    info_block = create_block(
        label=f"info-{label}",
        description=description,
        value=f"Memory Block ID: {memory_block_id}, Label: {label}, Key: {derive_key(label, salt=memory_block_id.encode(), length=32).hex()}",
    )
    return info_block
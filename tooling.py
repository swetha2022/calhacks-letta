# from letta import tool
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
import binascii
from letta_client import Letta

# @tool
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


# @tool
def create_memory_block(agentid, label: str, value: str, description: str):
    """
    create a memory block mapped to an info block that contains a key, location to memory block, and the label. Return info block.
    """
    token = os.getenv("LETTA_API_KEY")
    client = Letta(token=token)
    memory_block = client.blocks.create(
        label=label,
        description=description,
        value=value)

    info_block = create_info_block(memory_block.id, label, description="None")
    #attach info_block to agent and return info_block.id
    client.agents.blocks.attach(agent_id=agentid, block_id=info_block.id)

    #add to owner identity
    createOwnerIdentity(agentid, memory_block.id)
    return info_block

def create_info_block(memory_block_id, label, description):
    """
    create an info block that contains a key, location to memory block, and the label. Return info block.
    """
    token = os.getenv("LETTA_API_KEY")
    client = Letta(token=token)

    info_block = client.blocks.create(
        label=f"info-{label}",
        description=description,
        value=f"Memory Block ID: {memory_block_id}, Label: {label}, Key: {derive_key(label, salt=memory_block_id.encode(), length=32).hex()}",
    )
    return info_block

def createOwnerIdentity(agentid, memoryid): 
    #each memory is associated with an owner and the properties are the sharer's id and their info_data block id plus key to decrypt
    token = os.getenv("LETTA_API_KEY")
    client = Letta(token=token)
    identity = client.identities.create(
        agent_ids=[agentid], #owner
        identifier_key=str(memoryid), #memory block
        name=str(memoryid), 
        identity_type="other",
        properties=[] #sharer info to be filled when shared later
    )
    # client.agents.identities.attach(agent_id=agentid, identity_id=identity.id) #attach to owner
    return identity

    # identities = client.agents.retrieve(agent_state.id).identities
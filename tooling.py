# from letta import tool
import os 

from dotenv import load_dotenv #load env file
load_dotenv()

from letta_client import Letta
from crypto import derive_key, encrypt_value, decrypt_value

def get_client() -> Letta:
    token = os.getenv("LETTA_API_KEY")
    if not token or not token.strip():
        raise ValueError("LETTA_API_KEY missing/empty (check your .env and that load_dotenv() ran)")
    token = token.strip().strip('"').strip("'")  # guard against pasted quotes/spaces
    base_url = os.getenv("LETTA_API_BASE_URL")   # set if self-hosting; omit for cloud
    return Letta(token=token, base_url=base_url) if base_url else Letta(token=token)


# @tool
def create_memory_block(agentid, label: str, value: str, description: str):
    """
    create a memory block mapped to an info block that contains a key, location to memory block, and the label. Return info block.
    """
    client = get_client()
    memory_block = client.blocks.create(
        label=label,
        description=description,
        value=encrypt_value("enc", value),
    )
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
    client = get_client()
    value = f"Memory Block ID: {memory_block_id}, Label: {label}, Key: {derive_key(label, salt=memory_block_id.encode(), length=32).hex()}"
    info_block = client.blocks.create(
        label=f"info-{label}",
        description=description,
        value=encrypt_value("enc", value),
    )
    return info_block



#not shared to anyone but that one agent and no tooling should ever expose and get other agent's identities
#so should be secure
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


def find_identity(agent_id, memory_block_label):
    """Given an agent_id and a memory_block_label (e.g. 'human'),
    return the identity object (dict) whose name matches."""
    client = get_client()
    agent = client.agents.retrieve(agent_id)

    for i in agent.identities or []:
        if i.get("name") == memory_block_label:
            return i
    return None


def get_block_label(block_id: str) -> str | None:
    """Return the label of a block given its block_id."""
    client = get_client()
    block = client.blocks.retrieve(block_id)
    # block is usually a dict-like object
    return block.label
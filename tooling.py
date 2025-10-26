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
        name=str(memoryid), 
        identity_type="other",
        properties=[] #sharer info to be filled when shared later
    )
    return identity

# from letta import tool
import os, json

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
    encrypted_value, _ = encrypt_value("enc", value)

    memory_block = client.blocks.create(
        label=label,
        description=description,
        value=encrypted_value,
    )
    info_block, _ = create_info_block(memory_block.id, label, description="None")
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
    value = f'{{"Memory Block ID": "{memory_block_id}", "Label": "{label}", "Key": "{derive_key(label, salt=memory_block_id.encode(), length=32).hex()}"}}'
    encrypted_value, key = encrypt_value("enc", value)
    info_block = client.blocks.create(
        label=f"info-{label}",
        description=description,
        value=encrypted_value,
    )
    return info_block, key

# def read_memory(info_block_id) -> str:
#     """"
#     Given an info_block_id, go to the actual content block ID and read from the memory block
#     """
#     client = get_client()
#     info_block = client.blocks.retrieve(info_block_id) # Retrieve the info_block
#     print("decrypting info block...")
#     # print(decrypt_value(info_block))
#     info_block_dict = json.loads(decrypt_value(info_block).values) # Get value (description) as a dictionary
#     content_block_id = info_block_dict['Memory Block ID'] # Get content_block ID from dict
#     content_block = client.blocks.retrieve(content_block_id) # Retrieve content block from ID
#     decrypted_content = decrypt_value(content_block) # Decrypt content block value
#     return decrypted_content.value # Return data associated with content block

def read_memory(info_block_or_id, aad: bytes | None = None) -> str:
    """
    Given an *info* block (id/obj/dict), decrypt it to get the referenced
    content block id, then fetch & decrypt the content block and return plaintext.
    """
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
    info_plain = decrypt_value(enc_info, aad=aad)  # returns a plaintext string

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

    content_plain = decrypt_value(enc_content, aad=aad)  # plaintext string of your memory
    return content_plain


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

def add_property_to_identity(owner_agent_id, memory_block_label: str, borrower_agent_id, info_data_id, key):
    client = get_client()
    identity = find_identity(owner_agent_id, memory_block_label) # use owner agent id and memory block label to find identity
    if identity: # Only do this if identity is found
        new_property = {
            "borrower_id": borrower_agent_id,
            "info_data_id": info_data_id,
            "key": key,
        } # create new property
        props = identity.properties #get the properties list so we can append the new property
        props.append(new_property)
        client.identities.modify(identity_id=identity.id, properties=props) # modify the identity with the updated properties

def get_block_label(block_id: str) -> str | None:
    """Return the label of a block given its block_id."""
    client = get_client()
    block = client.blocks.retrieve(block_id)
    # block is usually a dict-like object
    return block.label
# from letta_client import Letta
# from tooling import create_info_block, find_identity, get_client, set_key
# from keystore import create_keystore
# from crypto import generate_rsa_keypair
# import os

# from pathlib import Path

# # client = Letta(token="sk-let-MWQzYTg2YTUtZGE4ZC00MWViLWJkMmYtZWMxY2NhOThkYzY3OjFjNjZkYzFhLWY5MWQtNDI3My04ZDJhLWEwYzc1ZjQwNTIxOA==")
# client = get_client()
# keystoreID=create_keystore().id

# # def define_agent_tools():
# #     # tools.append(client.tools.create(
# #     #     source_code=Path("tools/read_memory.py").read_text(),
# #     # ))
# #     # tools.append(client.tools.create(
# #     #     source_code=Path("tools/create_memory_block.py").read_text(),
# #     # ))
# #     # tools.append(client.tools.create(
# #     #     source_code=Path("tools/ring_an_agent.py").read_text(),
# #     # ))
# #     # tools.append(client.tools.create(
# #     #     source_code=Path("tools/send_message.py").read_text(),
# #     # ))
# #     # tools.append(client.tools.create(
# #     #     source_code=Path("tools/share_memory.py").read_text(),
# #     # ))
# #     # tools.append(client.tools.create(
# #     #     source_code=Path("tools/retrieve_memory.py").read_text(),
# #     # ))

# from pathlib import Path

# from typing import List
# def _read_text(path: str) -> str:
#     return Path(path).read_text(encoding="utf-8")

# def define_agent_tools() -> List[str]:
#     """
#     Create tools from `tooling.py` using Tools.create (source_code only, per docs).
#     Does NOT attach tools to any agent. Returns created tool IDs.
#     """
#     client: Letta = get_client()

#     # Single source file containing ALL tool functions
#     source_code = _read_text("tooling.py")

#     # Names/descriptions are only used for logging here; the Create API itself
#     # accepts just source_code per the docs.
#     catalog = [
#         ("read_memory", "Decrypt info block → fetch & decrypt content block"),
#         ("ring_an_agent", "Send an agent-to-agent message"),
#         ("send_message", "Send a user message to an agent and return reply"),
#         ("share_memory", "RSA-OAEP+PSS share of a memory pointer and key"),
#         ("retrieve_memory", "Verify+decrypt RSA bundle and import shared memory"),
#         ("create_memory_block", "Create encrypted memory + info block and attach to agent"),
#     ]

#     tool_ids: List[str] = []

#     for name, _desc in catalog:
#         tool = client.tools.create(
#             source_code=source_code  # per https://docs.letta.com/api-reference/tools/create
#         )
#         tool_id = getattr(tool, "id", None)
#         if not tool_id:
#             raise RuntimeError(f"Failed to create tool: {name}")
#         print(f"Created tool '{name}' → {tool_id}")
#         tool_ids.append(tool_id)

#     return tool_ids


# tool_ids = define_agent_tools()

# def create_agent(model_path, embedding_path, human_descriptor, persona_descriptor):
#     agent = client.agents.create(
#         model=model_path,
#         embedding=embedding_path,
#         # tool_ids=[tool.id for tool in tools],
#         tool_ids=tool_ids,
#     )
#     privatepem, publicpem = generate_rsa_keypair()
#     #store private pem
#     os.environ["PRIVATE_PEM"] = str(privatepem)

#     #store public pem in Keystore
#     set_key(agentid=agent.id, pubpem=publicpem, keystoreID=keystoreID)

#     create_memory_block(agent.id, label="human", value=human_descriptor, description="description of human")
#     create_memory_block(agent.id, label="persona", value=persona_descriptor, description="description of persona")
#     return agent


# agent_1 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Chad. They like vibe coding.", persona_descriptor="My name is Sam, a helpful assistant.")
# agent_2 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Alice. They enjoy painting.", persona_descriptor="My name is Eve, a helpful assistant.") 



# #TEST 
# #read from info block to get memory block content
# #get info block id first
# info_block = client.agents.retrieve(agent_1.id).blocks[0] #get first block attached to agent
# print(read_memory(info_block.get('id')))


# # get identifier key of existing memory block then create info block and send id of that info block
# identifier_key = find_identity(agent_1.id, "human").get("identifier_key")

# print(identifier_key)
# info_block, _ = create_info_block(identifier_key, label="key_info", description="identifier key of memory")

# # trigger_msg = f"Hey can you try sending a message '{memory_id_to_send}' to Alice? Their ID is {agent_2.id}"
# trigger_msg = f"Hey can you try sending a message '{info_block.id}' to Alice? Their ID is {agent_2.id}"

# response = send_message(agent_1.id, trigger_msg)
# print(response)

# response = send_message(agent_2.id, f"Hey can you read the memory block whose info block id is '{info_block.id}'?")
# print(response)




# letta.py

from letta_client import Letta
from tooling import (
    create_info_block,
    find_identity,
    get_client,
    create_memory_block,   # <-- add
    read_memory,           # <-- add
    send_message,          # <-- add
    set_key,               # reuse the one in tooling.py (consistent with get_key there)
    generate_rsa_keypair,  # use the one already defined in tooling.py
)
from keystore import create_keystore  # keep only create_keystore here
import os
from pathlib import Path
from typing import List

client = get_client()
keystoreID = create_keystore().id

from pathlib import Path

from typing import List
def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")

def define_agent_tools() -> List[str]:
    """
    Create tools from `tooling.py` using Tools.create (source_code only, per docs).
    Does NOT attach tools to any agent. Returns created tool IDs.
    """
    client: Letta = get_client()

    # Single source file containing ALL tool functions
    source_code = _read_text("tooling.py")

    # Names/descriptions are only used for logging here; the Create API itself
    # accepts just source_code per the docs.
    catalog = [
        ("read_memory", "Decrypt info block → fetch & decrypt content block"),
        ("ring_an_agent", "Send an agent-to-agent message"),
        ("send_message", "Send a user message to an agent and return reply"),
        ("share_memory", "RSA-OAEP+PSS share of a memory pointer and key"),
        ("retrieve_memory", "Verify+decrypt RSA bundle and import shared memory"),
        ("create_memory_block", "Create encrypted memory + info block and attach to agent"),
    ]

    tool_ids: List[str] = []

    for name, _desc in catalog:
        tool = client.tools.create(
            source_code=source_code  # per https://docs.letta.com/api-reference/tools/create
        )
        tool_id = getattr(tool, "id", None)
        if not tool_id:
            raise RuntimeError(f"Failed to create tool: {name}")
        print(f"Created tool '{name}' → {tool_id}")
        tool_ids.append(tool_id)

    return tool_ids

tool_ids = define_agent_tools()

def create_agent(model_path, embedding_path, human_descriptor, persona_descriptor):
    agent = client.agents.create(
        model=model_path,
        embedding=embedding_path,
        tool_ids=tool_ids,
    )
    privatepem, publicpem = generate_rsa_keypair()

    # store private pem (decode bytes → text)
    os.environ["PRIVATE_PEM"] = privatepem.decode("utf-8")

    # store public pem in Keystore
    set_key(agentid=agent.id, pubpem=publicpem, keystoreID=keystoreID)

    create_memory_block(agent.id, label="human", value=human_descriptor, description="description of human")
    create_memory_block(agent.id, label="persona", value=persona_descriptor, description="description of persona")
    return agent


agent_1 = create_agent(
    model_path="openai/gpt-4o-mini",
    embedding_path="openai/text-embedding-3-small",
    human_descriptor="The human's name is Chad. They like vibe coding.",
    persona_descriptor="My name is Sam, a helpful assistant."
)
agent_2 = create_agent(
    model_path="openai/gpt-4o-mini",
    embedding_path="openai/text-embedding-3-small",
    human_descriptor="The human's name is Alice. They enjoy painting.",
    persona_descriptor="My name is Eve, a helpful assistant."
)

# TESTS

#first 

# 1) Read from the first attached info block
# info_block = client.agents.retrieve(agent_1.id).blocks[0]
# print("Info Block:", type(info_block.get("id")))
# print(read_memory(info_block.get("id")))  # <- use .id (object), not .get('id')

# # 2) Create a temp info block pointing at the owner's 'human' memory id
# owner_identity = find_identity(agent_1.id, "human")
# identifier_key = owner_identity.identifier_key if hasattr(owner_identity, "identifier_key") else owner_identity.get("identifier_key")
# print(identifier_key)

# info_block, _ = create_info_block(identifier_key, label="key_info", description="identifier key of memory")

trigger_msg = f"Hey can you create a memory that contains the value '12345' then share it to Alice? Their ID is {agent_2.id}"
response = send_message(agent_1.id, trigger_msg)
print(response)

response = send_message(agent_2.id, f"Hey can you read the shared memory (use retrieve memory) given what {agent_1.id} just shared with you then tell me what memory you just learned?")
print(response)

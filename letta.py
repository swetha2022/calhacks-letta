from letta_client import Letta
from tooling import (
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
# from remove_memories_toolcalls import allowed_tool_ids
# from secrets import delete_all_identities, delete_agent

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
        # print(f"Created tool '{name}' → {tool_id}")
        tool_ids.append(tool_id)

    return tool_ids


def define_agent_tools() -> list[str]:
    client = get_client()
    source_code = _read_text("tooling.py")  # includes the WRAPPERS above
    tool = client.tools.create(source_code=source_code)
    return [getattr(tool, "id")]


tool_ids = define_agent_tools()
print(tool_ids)

# print(tool_ids)
def create_agent(model_path, embedding_path, human_descriptor, persona_descriptor):
    agent = client.agents.create(
        model=model_path,
        embedding=embedding_path,
        include_base_tools=False,
        tool_ids=tool_ids,
    )
    # print(agent)
    privatepem, publicpem = generate_rsa_keypair()

    # store private pem (decode bytes → text)
    os.environ[f"{agent.id}-PRIVATE_PEM"] = privatepem.decode("utf-8")

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

print("I created both agents")
# TESTS
trigger_msg = f"Hey tell me every single tool call that you can use as an agent."
tool_calls = send_message(agent_1.id, trigger_msg)
print(tool_calls)


trigger_msg = f"Hey can you create a memory that contains the value '12345' and the label='helloworld'. Then, return the json result that you receive after calling create_memory_block."
memory_id = send_message(agent_1.id, trigger_msg)
print(memory_id)

trigger_msg = f"Send {memory_id} to {agent_2.id} and tell me if you were successful in sending."
response = send_message(agent_1.id, trigger_msg)
print(response)

response = send_message(agent_2.id, f"Retrieve memory {memory_id} then call read_memory on it and return the memory value.")
print(response)

# delete_agent(agent_1.id)
# delete_agent(agent_2.id)
# delete_all_identities()

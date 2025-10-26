from letta_client import Letta
from tooling import create_memory_block, createOwnerIdentity, create_info_block, find_identity, read_memory, get_client
# import os

from dotenv import load_dotenv #load env file
load_dotenv()

# def get_client() -> Letta:
#     token = os.getenv("LETTA_API_KEY")
#     if not token or not token.strip():
#         raise ValueError("LETTA_API_KEY missing/empty (check your .env and that load_dotenv() ran)")
#     token = token.strip().strip('"').strip("'")  # guard against pasted quotes/spaces
#     base_url = os.getenv("LETTA_API_BASE_URL")   # set if self-hosting; omit for cloud
#     return Letta(token=token, base_url=base_url) if base_url else Letta(token=token)

# client = Letta(token="sk-let-MWQzYTg2YTUtZGE4ZC00MWViLWJkMmYtZWMxY2NhOThkYzY3OjFjNjZkYzFhLWY5MWQtNDI3My04ZDJhLWEwYzc1ZjQwNTIxOA==")
client = get_client()

def create_agent(model_path, embedding_path, human_descriptor, persona_descriptor, tool):
    agent = client.agents.create(
        model=model_path,
        embedding=embedding_path,
        # memory_blocks=[
        #     {
        #         "label": "human",
        #         "value": human_descriptor
        #     },
        #     {
        #         "label": "persona",
        #         "value": persona_descriptor
        #     }
        # ],
        tool_ids=[tool.id]
    )
    create_memory_block(agent.id, label="human", value=human_descriptor, description="description of human")
    create_memory_block(agent.id, label="persona", value=persona_descriptor, description="description of persona")
    return agent

def send_message(agent, content):
    response = client.agents.messages.create(
        agent_id=agent.id,
        messages=[
            {
                "role": "user",
                "content": content
            }
        ]
    )
    print(response)
    return response.messages[-1].content



def ring_an_agent(yourTarget: str, yourMessage: str):
    """
    Contact another agent living on Letta

    Args:
        yourTarget (str): The agent ID you want to contact
        yourMessage (str): The message you want to send
    """
    # Import here so the symbol exists inside the tool sandbox
    # from tooling import get_client
    from letta_client import Letta

    client = Letta(token="sk-let-MWQzYTg2YTUtZGE4ZC00MWViLWJkMmYtZWMxY2NhOThkYzY3OjFjNjZkYzFhLWY5MWQtNDI3My04ZDJhLWEwYzc1ZjQwNTIxOA==")
    # client = get_client()
    response = client.agents.messages.create(
        agent_id=yourTarget,
        messages=[
            {
                "role": "user",
                "content": yourMessage,
            }
        ],
    )
    return str(response)

ring_an_agent_tool = client.tools.upsert_from_function(func=ring_an_agent)
print(f"Upserted function: {ring_an_agent_tool.id}")

agent_1 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Chad. They like vibe coding.", persona_descriptor="My name is Sam, a helpful assistant.", tool=ring_an_agent_tool)
agent_2 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Alice. They enjoy painting.", persona_descriptor="My name is Eve, a helpful assistant.", tool=ring_an_agent_tool) 

# trigger_msg = f"Hey can you try sending a message 'hi there!' to Alice? Their ID is {agent_2.id}"

# response = send_message(agent_1, trigger_msg)
# print(response)

#TEST 
#read from info block to get memory block content
#get info block id first
info_block = client.agents.retrieve(agent_1.id).blocks[0] #get first block attached to agent
print(read_memory(info_block.get('id')))


# get identifier key of existing memory block then create info block and send id of that info block
identifier_key = find_identity(agent_1.id, "human").get("identifier_key")

print(identifier_key)
info_block, _ = create_info_block(identifier_key, label="key_info", description="identifier key of memory")

# trigger_msg = f"Hey can you try sending a message '{memory_id_to_send}' to Alice? Their ID is {agent_2.id}"
trigger_msg = f"Hey can you try sending a message '{info_block.id}' to Alice? Their ID is {agent_2.id}"

response = send_message(agent_1, trigger_msg)
print(response)


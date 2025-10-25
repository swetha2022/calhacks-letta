from letta_client import Letta

client = Letta(token="sk-let-MWQzYTg2YTUtZGE4ZC00MWViLWJkMmYtZWMxY2NhOThkYzY3OjFjNjZkYzFhLWY5MWQtNDI3My04ZDJhLWEwYzc1ZjQwNTIxOA==")

def create_agent(model_path, embedding_path, human_descriptor, persona_descriptor):
    agent = client.agents.create(
        model=model_path,
        embedding=embedding_path,
        memory_blocks=[
            {
                "label": "human",
                "value": human_descriptor
            },
            {
                "label": "persona",
                "value": persona_descriptor
            }
        ],
        tools=["web_search", "run_code"]
    )
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
    return response.messages[-1].content 

def attach_tool(agent, tool_id):
    client.agents.tools.attach(
        agent_id=agent.id,
        tool_id=tool_id,
    )

def detach_tool(agent, tool_id):
    client.agents.tools.detach(
        agent_id=agent.id,
        tool_id=tool_id,
    )


# the agent will think, then edit its memory using a tool
# for message in response.messages:
#     print(message)

# The content of this memory block will be something like
# "The human's name is Brad. They like vibe coding."
# Fetch this block's content with:

agent_1 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Chad. They like vibe coding.", persona_descriptor="My name is Sam, a helpful assistant.")
agent_2 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Alice. They enjoy painting.", persona_descriptor="My name is Eve, a helpful assistant.") 

response_2 = send_message(agent_2, "How are you?") 
print(response_2) 

response_1 = send_message(agent_1, "How are you?") 
print(response_1) 

# human_block = client.agents.blocks.retrieve(agent_id=agent_state.id, block_label="human")
# print(human_block.value) 

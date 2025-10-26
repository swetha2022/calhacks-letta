from letta_client import Letta

client = Letta(token="sk-let-MWQzYTg2YTUtZGE4ZC00MWViLWJkMmYtZWMxY2NhOThkYzY3OjFjNjZkYzFhLWY5MWQtNDI3My04ZDJhLWEwYzc1ZjQwNTIxOA==")

def create_agent(model_path, embedding_path, human_descriptor, persona_descriptor, tool):
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
        tool_ids=[tool.id]
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
    print(response)
    return response.messages[-1].content

def ring_an_agent(yourTarget: str, yourMessage: str):
    """
    Contact another agent living on Letta

    Args:
        yourTarget (str): The agent ID you want to contact
        yourMessage (str): The message you want to send
    """
    from letta_client import Letta

    client = Letta(token="sk-let-MWQzYTg2YTUtZGE4ZC00MWViLWJkMmYtZWMxY2NhOThkYzY3OjFjNjZkYzFhLWY5MWQtNDI3My04ZDJhLWEwYzc1ZjQwNTIxOA==")

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

trigger_msg = f"Hey can you try sending a message 'hi there!' to Alice? Their ID is {agent_2.id}"

response = send_message(agent_1, trigger_msg)
print(response)
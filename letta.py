from letta_client import Letta

client = Letta(token="sk-let-MWQzYTg2YTUtZGE4ZC00MWViLWJkMmYtZWMxY2NhOThkYzY3OjFjNjZkYzFhLWY5MWQtNDI3My04ZDJhLWEwYzc1ZjQwNTIxOA==")

def create_agent(model_path, embedding_path, human_descriptor, persona_descriptor, tags, tools):
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
        tags=tags,
        tools=tools
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

def modify_memory(agent, block_label, updated_value): 
    client.agents.blocks.modify(
        agent_id=agent.id,
        block_label=block_label,
        value=updated_value
    )

def retrieve_memory_block(agent, block_label):
    return client.agents.blocks.retrieve(
        agent_id=agent.id,
        block_label=block_label
    )

agent_1 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Chad. They like vibe coding.", persona_descriptor="My name is Sam, a helpful assistant.", tags=["agent_1"], tools=["web_search", "run_code", "send_message_to_agents_matching_all_tags"])
agent_2 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Alice. They enjoy painting.", persona_descriptor="My name is Eve, a helpful assistant.", tags=["agent_2"], tools=["web_search", "run_code", "send_message_to_agents_matching_all_tags"]) 

query_agent2 = f"Hey - just letting you know I'm going to connect you with another one of my agent buddies. Hope you enjoy chatting with them (I think they'll reach out directly). When you receive their message, send a message back to agent with tag agent_1."
print(send_message(agent_2, query_agent2))
print() 

query_agent1 = f"Hey, my other agent friend is lonely and needs someone to chat to. Can you give them a ring? Their ID is {agent_2.id}. If you can reach them, they will message back and tell me what they said."
print(send_message(agent_1, query_agent1))
print()
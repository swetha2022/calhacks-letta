from letta_client import Letta
from letta_client.client import BaseTool
from pydantic import BaseModel
from typing import Type

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

# class MsgSendArgs(BaseModel):
#     target_agent_id: str
#     message_contents: str

# class MsgSendTool(BaseTool):
#     name: str = "msg_send"
#     args_schema: Type[BaseModel] = MsgSendArgs
#     description: str = "Send a custom message to another agent."

#     def __init__(self, client):
#         super().__init__()
#         self.client = client

#     def run(self, target_agent_id, message_contents):
#         response = client.agents.send_message_async(
#             agent_id=target_agent_id,
#             message=message_contents,
#         )
#         return response 

def msg_send_agent(agentId: str, message: str):
    """
    Send a message to another agent.

    Args:
        agentId (str): The ID of the target agent to send a message to.
        message (str): The message content.

    Returns:
        The response from the agent after receiving the message.
    """
    from letta_client import Letta
    client = Letta(token="sk-let-MWQzYTg2YTUtZGE4ZC00MWViLWJkMmYtZWMxY2NhOThkYzY3OjFjNjZkYzFhLWY5MWQtNDI3My04ZDJhLWEwYzc1ZjQwNTIxOA==")
    
    response = client.agents.messages.create(
        agent_id=agentId,
        messages=[{
            "role": "user",
            "content": f"[message from another agent] {message}"
        }]
    )
    return str(response)

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

tool = client.tools.create_from_function(func=msg_send_agent)
#tool = client.tools.upsert_from_function(func=msg_send_agent)
agent_1 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Chad. They like vibe coding.", persona_descriptor="My name is Sam, a helpful assistant.", tags=["agent_1"], tools=["web_search", "run_code", "msg_send_agent"])
agent_2 = create_agent(model_path="openai/gpt-4o-mini", embedding_path="openai/text-embedding-3-small", human_descriptor="The human's name is Alice. They enjoy painting.", persona_descriptor="My name is Eve, a helpful assistant.", tags=["agent_2"], tools=["web_search", "run_code", "msg_send_agent"]) 

query_agent2 = f"Hey - just letting you know I'm going to connect you with another one of my agent buddies. Hope you enjoy chatting with them (I think they'll reach out directly). When you receive their message, send a message back to the agent."
print(send_message(agent_2, query_agent2))
print() 

query_agent1 = f"Hey, my other agent friend is lonely and needs someone to chat to. Can you give them a ring? Their ID is {agent_2.id}. If you can reach them, they will message back and tell me what they said."
print(send_message(agent_1, query_agent1))
print()
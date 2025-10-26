from __future__ import annotations
import os, json

from dotenv import load_dotenv #load env file
load_dotenv()

from letta_client import Letta

from typing import Optional

# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.asymmetric import padding, rsa
# from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
# from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
from base64 import b64encode, b64decode


def get_client() -> Letta:
    token = os.getenv("LETTA_API_KEY")
    if not token or not token.strip():
        raise ValueError("LETTA_API_KEY missing/empty (check your .env and that load_dotenv() ran)")
    token = token.strip().strip('"').strip("'")  # guard against pasted quotes/spaces
    base_url = os.getenv("LETTA_API_BASE_URL")   # set if self-hosting; omit for cloud
    return Letta(token=token, base_url=base_url) if base_url else Letta(token=token)


def send_message(agentid:str, content:str):
    """
    Send a user message to a specified Letta agent and return the agent's latest reply.
    This should be used for user-agent communications (NOT agent-agent communications).

    Args:
        agentid (str): The unique ID of the Letta agent to which the message will be sent.
            This should be the string identifier returned by Letta (e.g., "agent-1234abcd").
        content (str): The text content of the user message to send to the agent.

    Returns:
        str: The plaintext content of the agent's most recent response message.

    Description:
        This function sends a message on behalf of the user to a target agent
        using the Letta SDK's message API. It posts the provided text content
        to the specified agent's message thread and returns the plaintext content
        of the agent's reply. The full message response object is printed for
        debugging purposes.

    Example:
        >>> reply = send_message("agent-1234abcd", "Hello! What can you do?")
        >>> print(reply)
        "Hi! I'm your Letta assistant — ready to help."
    """
    client = get_client()
    response = client.agents.messages.create(
        agent_id=agentid,
        messages=[
            {
                "role": "user",
                "content": content
            }
        ]
    )
    print(response)
    return response.messages[-1].content



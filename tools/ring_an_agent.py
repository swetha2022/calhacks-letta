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


def ring_an_agent(yourTarget: str, yourMessage: str):
    """
    Contact another agent living on Letta. 
    This should be used for agent-agent communications (NOT user-agent communications).

    Args:
        yourTarget (str): The agent ID you want to contact
        yourMessage (str): The message you want to send
    """
    # Import here so the symbol exists inside the tool sandbox
    # from tooling import get_client
    # from letta_client import Letta

    # client = Letta(token="sk-let-MWQzYTg2YTUtZGE4ZC00MWViLWJkMmYtZWMxY2NhOThkYzY3OjFjNjZkYzFhLWY5MWQtNDI3My04ZDJhLWEwYzc1ZjQwNTIxOA==")
    client = get_client()
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
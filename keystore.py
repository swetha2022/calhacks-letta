from letta_client import Letta
from tooling import get_client

def create_keystore(): #just a block
    client = get_client()
    keystore = client.blocks.create(
        label="Keystore",
        description="Keystore storing all public keys for every user",
        value="",
    )
    return keystore

# def set_key(agentid, pubpem, keystoreID):
#     client = get_client()
#     keystoreBlock = client.blocks.retrieve(keystoreID) #get keystore block

#     current_value = keystoreBlock.value

#     # Ensure it's a dict
#     if not isinstance(current_value, dict):
#         raise TypeError("Keystore value is not a dictionary")

#     # Update or insert the key
#     current_value[agentid] = pubpem

#     # Push updated value back
#     keystore = client.blocks.modify(keystoreID, {value: current_value})

#     return keystore

import json
def set_key(agentid: str, pubpem, keystoreID: str):
    client = get_client()

    # Retrieve the existing keystore block
    block = client.blocks.retrieve(keystoreID)
    raw = getattr(block, "value", None)

    # Parse value → dict
    try:
        store = json.loads(raw) if raw else {}
        if not isinstance(store, dict):
            store = {}
    except Exception:
        store = {}

    # Normalize inputs
    agentid = str(agentid)
    if isinstance(pubpem, bytes):
        pubpem = pubpem.decode("utf-8")

    # Update mapping
    store[agentid] = pubpem

    # Write back (API wants value=string, not dict)
    updated = client.blocks.modify(
        keystoreID,
        value=json.dumps(store, separators=(",", ":"))
    )

    return updated



def get_key(agentid, keystoreID):
    client = get_client()
    keystoreBlock = client.blocks.retrieve(keystoreID) #get keystore block

    current_value = keystoreBlock.get("value", {})

    return current_value[agentid]


"""
- Sharing: 
    - Info block contains metadata for memory block (who owns, where its located, etc.) 
    - Encrypt the info block contents using a random key (this sits somewhere outside like client.create block)
    - Passing to other agent —> id of this info block in order to pass this along and the random key together as one cipher text encrypted by the recipient’s public key
        - One cipher text 
    - Decryption: decrypt cipher text to get the random key, use random key to decrypt the cipher text to get info block id -> can get info block containing metadata for memory block 
- Revocation: 
"""

from crypto import derive_key, encrypt_value
import os 
from letta import send_message
from tooling import add_property_to_identity

"""
call find identity to get memory id
call create info block
encrypt infoblock.id plus key using public key encryption
pass to next agent
"""

def share_memory(agent, recipient_agent_id):
    """
    agent_id: the id of the agent who is sharing
    """

    memory_id = find_identity(agent.id, "human").get("identifier_key")
    info_block, random_key = create_info_block(memory_id, label="key_info", description="identifier key of memory")

    salt_1 = os.urandom(16)
    salt_2 = os.urandom(16)

    public_key = get_public_key(recipient_agent_id) 
    
    ciphertext_one, _ = rsa_oaep_pss_encrypt(label="enc", salt=salt_1, key=public_key, plaintext=str(info_block.id)) # plain text is random key + info_block.id
    
    ciphertext_two, _ = rsa_oaep_pss_encrypt(label="enc", salt=salt_2, key=public_key, plaintext=str(random_key))
    
    # add_property_to_identity(owner_agent_id=agent.id)
    
    trigger_msg = f"Hey can you try sending a message '{ciphertext_one}' and ciphertext of random key '{ciphertext_two}' to Alice? Their ID is {recipient_agent_id}"
    
    response = send_message(agent, trigger_msg)
    print(response)


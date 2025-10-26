

"""
- Sharing: 
    - Info block contains metadata for memory block (who owns, where its located, etc.) 
    - Encrypt the info block contents using a random key (this sits somewhere outside like client.create block)
    - Passing to other agent —> id of this info block in order to pass this along and the random key together as one cipher text encrypted by the recipient’s public key
        - One cipher text 
    - Decryption: decrypt cipher text to get the random key, use random key to decrypt the cipher text to get info block id -> can get info block containing metadata for memory block 
- Revocation: 
"""

from crypto import derive_key, encrypt_value, rsa_oaep_pss_encrypt, rsa_oaep_pss_decrypt
import os 
from letta import send_message, keystoreID
from tooling import add_property_to_identity, find_identity, create_info_block, read_memory, create_memory_block, get_block_label
from keystore import get_key

from dotenv import load_dotenv #load env file
load_dotenv()

"""
call find identity to get memory id
call create info block
encrypt infoblock.id plus key using public key encryption
pass to next agent
"""
def share_memory(sender_agent, recipient_agent_id, memory_block_id):
    """
    agent_id: the id of the agent who is sharing
    """
    memory_id = find_identity(sender_agent.id, "human").get("identifier_key")
    info_block, random_key = create_info_block(memory_id, label="key_info", description="identifier key of memory")

    recipient_public_key = get_key(recipient_agent_id, keystoreID) 
    sender_private_key = os.getenv("PRIVATE_PEM")
    
    ciphertext_one = rsa_oaep_pss_encrypt(plaintext=info_block.id, recipient_rsa_pub_pem=recipient_public_key, sender_rsapss_priv_pem=sender_private_key) # plain text is random key + info_block.id
    
    ciphertext_two = rsa_oaep_pss_encrypt(plaintext=random_key.decode(), recipient_rsa_pub_pem=recipient_public_key, sender_rsapss_priv_pem=sender_private_key)
    
    add_property_to_identity(owner_agent_id=sender_agent.id, memory_block_label=get_block_label(block_id=memory_block_id), borrower_agent_id=recipient_agent_id, info_data_id=info_block.id, key=random_key)
    
    trigger_msg = f"Hey can you try sending a message '{ciphertext_one}' and ciphertext of random key '{ciphertext_two}' to Alice? Their ID is {recipient_agent_id}. My sender ID is {sender_agent.id}"
    
    response = send_message(sender_agent, trigger_msg)
    print(response)





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



def retrieve_memory(recipient_agent, sender_agent_id, ciphertext_one, ciphertext_two): 
    recipient_private_key = os.getenv("PRIVATE_PEM")
    sender_public_key = get_key(sender_agent_id, keystoreID) 

    plaintext_one = rsa_oaep_pss_decrypt(bundle_json=ciphertext_one, recipient_rsa_priv_pem=recipient_private_key, sender_rsapss_pub_pem=sender_public_key)
    plaintext_two = rsa_oaep_pss_decrypt(bundle_json=ciphertext_two, recipient_rsa_priv_pem=recipient_private_key, sender_rsapss_pub_pem=sender_public_key)

    info_block_id = plaintext_one
    random_key = plaintext_two.encode()

    memory_block_content = read_memory(info_block_or_id=info_block_id, key=random_key)

    create_memory_block(agentid=recipient_agent.id, label="persona", value=memory_block_content, description='shared memory from ' + sender_agent_id)
    
    
    


   

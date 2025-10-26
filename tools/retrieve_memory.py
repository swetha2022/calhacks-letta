from __future__ import annotations
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, json
import binascii
from base64 import b64encode, b64decode

from letta_client import Letta

from dotenv import load_dotenv #load env file
load_dotenv()

def get_client() -> Letta:
    token = os.getenv("LETTA_API_KEY")
    if not token or not token.strip():
        raise ValueError("LETTA_API_KEY missing/empty (check your .env and that load_dotenv() ran)")
    token = token.strip().strip('"').strip("'")  # guard against pasted quotes/spaces
    base_url = os.getenv("LETTA_API_BASE_URL")   # set if self-hosting; omit for cloud
    return Letta(token=token, base_url=base_url) if base_url else Letta(token=token)


def get_key(agentid, keystoreID):
    client = get_client()
    keystoreBlock = client.blocks.retrieve(keystoreID) #get keystore block

    current_value = keystoreBlock.get("value", {})

    return current_value[agentid]

def rsa_oaep_pss_decrypt(
    bundle_json: str,
    *,
    recipient_rsa_priv_pem: bytes | str,
    sender_rsapss_pub_pem: bytes | str,
    recipient_priv_password: Optional[bytes] = None,
    aad: Optional[bytes] = None,
) -> str:
    """
    Verify RSA-PSS signature first, then RSA-OAEP decrypt.
    Requires the same AAD bytes used at encryption (if any).
    """
    try:
        b = json.loads(bundle_json)
        if b.get("scheme") != SCHEME_ID:
            raise ValueError("Unsupported or mismatched scheme")
        ct = _b64d(b["ct_b64"])
        sig = _b64d(b["sig_b64"])
        aad_hash_stored = _b64d(b["aad_sha256_b64"])
    except (KeyError, ValueError, binascii.Error, json.JSONDecodeError) as e:
        raise ValueError("Invalid RSA bundle") from e

    aad_bytes = aad if aad is not None else b""
    aad_hash = _sha256(aad_bytes)
    if aad_hash != aad_hash_stored:
        raise ValueError("AAD mismatch")

    verifier = _load_pub(sender_rsapss_pub_pem)
    to_verify = _to_sign(aad_hash, ct)
    try:
        verifier.verify(
            sig,
            to_verify,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as e:
        raise ValueError("Invalid signature") from e

    priv = _load_priv(recipient_rsa_priv_pem, password=recipient_priv_password)
    pt = priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=aad_bytes if aad_bytes else None,
        ),
    )
    return pt.decode("utf-8")

def create_memory_block(agentid: str, label: str, value: str, description: str) -> dict:
    """
    Create a memory block and attach a corresponding info block to the given agent.

    Args:
        agentid (str): The ID of the agent that will own/attach the blocks.
        label (str): Label to assign to the new memory block.
        value (str): Plaintext content to encrypt and store in the memory block.
        description (str): Human-readable description for the memory block.

    Returns:
        dict: A JSON-serializable summary containing the created block IDs.
            Example:
            {
                "memory_block_id": "block-...",
                "info_block_id": "block-..."
            }
    """
    client = get_client()

    # Encrypt plaintext before storing
    encrypted_value, _ = encrypt_value("enc", value)

    # Create the memory block
    memory_block = client.blocks.create(
        label=label,
        description=description,
        value=encrypted_value,
    )

    # Create the info block that points to the memory block
    info_block, _ = create_info_block(
        memory_block.id,
        label=label,
        description="Pointer to memory block"
    )

    # Attach the info block to the agent
    client.agents.blocks.attach(agent_id=agentid, block_id=info_block.id)

    # Update owner identity mapping (if your helper does that)
    createOwnerIdentity(agentid, memory_block.id)

    # ✅ Return JSON-serializable data (avoid returning SDK objects)
    return {
        "memory_block_id": getattr(memory_block, "id", None),
        "info_block_id": getattr(info_block, "id", None),
    }
    
def retrieve_memory(recipient_agent, sender_agent_id, ciphertext_one, ciphertext_two, keystoreID): 
    recipient_private_key = os.getenv("PRIVATE_PEM")
    sender_public_key = get_key(sender_agent_id, keystoreID) 

    plaintext_one = rsa_oaep_pss_decrypt(bundle_json=ciphertext_one, recipient_rsa_priv_pem=recipient_private_key, sender_rsapss_pub_pem=sender_public_key)
    plaintext_two = rsa_oaep_pss_decrypt(bundle_json=ciphertext_two, recipient_rsa_priv_pem=recipient_private_key, sender_rsapss_pub_pem=sender_public_key)

    info_block_id = plaintext_one
    random_key = plaintext_two.encode()

    memory_block_content = read_memory(info_block_or_id=info_block_id, key=random_key)

    create_memory_block(agentid=recipient_agent.id, label="persona", value=memory_block_content, description='shared memory from ' + sender_agent_id)
    
    
    


   

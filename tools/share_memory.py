import os 
from typing import Optional
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

def find_identity(agent_id, memory_block_label):
    """Given an agent_id and a memory_block_label (e.g. 'human'),
    return the identity object (dict) whose name matches."""
    client = get_client()
    agent = client.agents.retrieve(agent_id)

    for i in agent.identities or []:
        if i.get("name") == memory_block_label:
            return i
    return None

def create_info_block(memory_block_id, label, description):
    """
    create an info block that contains a key, location to memory block, and the label. Return info block.
    """
    client = get_client()
    value = f'{{"Memory Block ID": "{memory_block_id}", "Label": "{label}", "Key": "{derive_key(label, salt=memory_block_id.encode(), length=32).hex()}"}}'
    encrypted_value, key = encrypt_value("enc", value)
    info_block = client.blocks.create(
        label=f"info-{label}",
        description=description,
        value=encrypted_value,
    )
    return info_block, key

def get_key(agentid, keystoreID):
    """
    Retrieve the stored public key (PEM string) for a given agent
    from a keystore block in Letta.

    The keystore block's `.value` field is expected to contain a JSON
    string mapping agent IDs to their corresponding public keys.

    """
    client = get_client()
    keystoreBlock = client.blocks.retrieve(keystoreID) #get keystore block

    current_value = keystoreBlock.get("value", {})

    return current_value[agentid]

def encrypt_value(label: str, plaintext: str, aad: bytes | None = None) -> str:
    """
    Encrypt a UTF-8 string using AES-GCM with a per-entry random salt and nonce.
    Returns a JSON string containing salt, nonce, and ciphertext (all base64).

    Args:
        label: Domain label for key derivation (e.g., "enc").
        plaintext: The string to encrypt.
        aad: Optional associated data to bind into the AEAD (not stored).
    """
    if not isinstance(plaintext, str):
        raise TypeError("encrypt_value expects plaintext as str")
    # Per-memory salt (for HKDF) and nonce (for AES-GCM)
    salt = os.urandom(16)
    key = derive_key(label, salt=salt, length=32)  # 256-bit key
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM standard nonce size
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

    bundle = {
        "alg": "AESGCM",
        "kdf": "HKDF-SHA256",
        "label": label,
        "salt_b64": b64encode(salt).decode("ascii"),
        "nonce_b64": b64encode(nonce).decode("ascii"),
        "ct_b64": b64encode(ct).decode("ascii"),
        # NOTE: AAD is not stored; if you use AAD, the decryptor must supply the same bytes.
    }
    return json.dumps(bundle, separators=(",", ":")), key

def rsa_oaep_pss_encrypt(
    plaintext: str,
    *,
    recipient_rsa_pub_pem: bytes | str,
    sender_rsapss_priv_pem: bytes | str,
    sender_priv_password: Optional[bytes] = None,
    aad: Optional[bytes] = None,
) -> str:
    """
    Encrypt with RSA-OAEP(SHA-256) and sign the resulting ciphertext using RSA-PSS(SHA-256).
    AAD (if provided) is *not* stored; its SHA-256 is included in the signature and also used
    as the OAEP label (binding AAD at both layers).
    Returns a JSON bundle with {scheme, ct_b64, sig_b64, aad_sha256_b64}.
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be str")

    pub = _load_pub(recipient_rsa_pub_pem)
    signer = _load_priv(sender_rsapss_priv_pem, password=sender_priv_password)

    aad_bytes = aad if aad is not None else b""
    aad_hash = _sha256(aad_bytes)

    # RSA-OAEP encrypt (bind AAD via label)
    ct = pub.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=aad_bytes if aad_bytes else None,
        ),
    )

    # RSA-PSS signature over (scheme || aad_hash || ct)
    to_sign = _to_sign(aad_hash, ct)
    sig = signer.sign(
        to_sign,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    bundle = {
        "scheme": SCHEME_ID,
        "ct_b64": _b64(ct),
        "sig_b64": _b64(sig),
        "aad_sha256_b64": _b64(aad_hash),
    }
    return json.dumps(bundle, separators=(",", ":"))

def add_property_to_identity(owner_agent_id, memory_block_label: str, borrower_agent_id, info_data_id, key):
    client = get_client()
    identity = find_identity(owner_agent_id, memory_block_label) # use owner agent id and memory block label to find identity
    if identity: # Only do this if identity is found
        new_property = {
            "borrower_id": borrower_agent_id,
            "info_data_id": info_data_id,
            "key": key,
        } # create new property
        props = identity.properties #get the properties list so we can append the new property
        props.append(new_property)
        client.identities.modify(identity_id=identity.id, properties=props) # modify the identity with the updated properties

def get_block_label(block_id: str) -> str | None:
    """Return the label of a block given its block_id."""
    client = get_client()
    block = client.blocks.retrieve(block_id)
    # block is usually a dict-like object
    return block.label

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

def share_memory(sender_agentid:str, recipient_agent_id:str, memory_block_id:str, keystoreID:str):
    """
    Securely share an encrypted memory block with another agent using public-key encryption.

    Args:
        sender_agentid (str): The Letta agent id initiating the share operation.
        recipient_agent_id (str): The unique ID of the recipient agent who will receive the shared memory.
        memory_block_id (str): The ID of the original memory block that the sender wants to share.
        keystoreID (str): The ID of the keystore block containing the recipient's public key.

    Returns:
        None. Prints the response message from the send operation.

    Description:
        This function enables one agent to share a memory block with another agent using
        hybrid RSA-OAEP/PSS encryption for confidentiality and authenticity.

        The steps are:
            1. Retrieve the sender's identity key for their "human" label via `find_identity()`.
            2. Create a temporary `info_block` (and random symmetric key) referencing that identity.
            3. Retrieve the recipient's public RSA key from the keystore and the sender's private key
               from the `PRIVATE_PEM` environment variable.
            4. Encrypt both the info block ID and the random key:
               - `ciphertext_one` = RSA-OAEP/PSS encryption of the info block ID.
               - `ciphertext_two` = RSA-OAEP/PSS encryption of the random symmetric key.
            5. Add a record of this sharing event to the sender’s identity using
               `add_property_to_identity()`, associating the memory label, borrower, and key info.
            6. Construct a trigger message instructing the recipient agent to receive and decrypt
               the shared memory, then send that message using `send_message()`.

        The function prints the response from the Letta API after the message is sent.

    Raises:
        ValueError: If required identity keys or keystore entries are missing.
        RuntimeError: If encryption or messaging fails due to missing keys or invalid agent IDs.
    """
    memory_id = find_identity(sender_agentid, "human").get("identifier_key")
    info_block, random_key = create_info_block(memory_id, label="key_info", description="identifier key of memory")

    recipient_public_key = get_key(recipient_agent_id, keystoreID) 
    sender_private_key = os.getenv("PRIVATE_PEM")
    sender_private_key = sender_private_key.encode("utf-8")
    
    ciphertext_one = rsa_oaep_pss_encrypt(plaintext=info_block.id, recipient_rsa_pub_pem=recipient_public_key, sender_rsapss_priv_pem=sender_private_key) # plain text is random key + info_block.id
    
    ciphertext_two = rsa_oaep_pss_encrypt(plaintext=random_key.decode(), recipient_rsa_pub_pem=recipient_public_key, sender_rsapss_priv_pem=sender_private_key)
    
    add_property_to_identity(owner_agent_id=sender_agentid, memory_block_label=get_block_label(block_id=memory_block_id), borrower_agent_id=recipient_agent_id, info_data_id=info_block.id, key=random_key)
    
    trigger_msg = f"Hey can you try sending a message '{ciphertext_one}' and ciphertext of random key '{ciphertext_two}' to Alice? Their ID is {recipient_agent_id}. My sender ID is {sender_agent.id}"
    
    response = send_message(sender_agentid, trigger_msg)
    print(response)

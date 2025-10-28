from __future__ import annotations
import os, json
from typing import Optional, Union

from dotenv import load_dotenv #load env file
load_dotenv()

from letta_client import Letta

from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.exceptions import InvalidSignature

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

def derive_key(label: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derive a single key (e.g., encryption or authentication) from the master key using HKDF.

    Args:
        label: Either "enc" or "auth" — determines the key domain.
        salt:  A per-memory or per-session salt (e.g., memory ID bytes).
        length: Desired key length in bytes (default 32).
    """
    # Load master key from environment (expected as hex string)
    master_hex = os.getenv("MASTER_PRIVATE_KEY")
    if not master_hex:
        raise ValueError("Missing environment variable: MASTER_PRIVATE_KEY")

    try:
        master_key = binascii.unhexlify(master_hex)
    except Exception as e:
        raise ValueError("MASTER_PRIVATE_KEY must be a valid hex string") from e

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=f"letta/agent-memory/v1/{label}".encode("utf-8"),  # domain separation
    )
    derived_key = hkdf.derive(master_key)
    return derived_key


def create_info_block(memory_block_id, label, description):
    """
    create an info block that contains a key, location to memory block, and the label. Return info block.
    """
    client = get_client()
    value = f'{{"Memory Block ID": "{memory_block_id}", "Label": "{label}", "Key": "{derive_key(label, salt=memory_block_id.encode(), length=32).hex()}"}}'
    encrypted_value, key = encrypt_value("enc", value)
    info_block = client.blocks.create(
        label=f"info-{label}",
        entity_id=f"info-{label}",
        description=description,
        value=encrypted_value,
    )
    return info_block, key

#not shared to anyone but that one agent and no tooling should ever expose and get other agent's identities
#so should be secure
def createOwnerIdentity(agentid, memoryid): 
    """each memory is associated with an owner and the properties are the sharer's id and their info_data block id plus key to decrypt
    """
    client = get_client()
    identity = client.identities.create(
        agent_ids=[agentid], #owner
        identifier_key=str(memoryid), #memory block
        name=get_block_label(memoryid), 
        identity_type="other",
        properties=[] #sharer info to be filled when shared later
    )
    return identity

def find_identity(agent_id, memory_block_label):
    """Given an agent_id and a memory_block_label (e.g. 'human'),
    return the identity object (dict) whose name matches."""
    client = get_client()
    agent = client.agents.retrieve(agent_id)

    for i in agent.identities or []:
        if i.get("name") == memory_block_label:
            return i
    return None

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
    return block.id

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

def decrypt_value(enc_bundle_json: str, aad: bytes | None = None, key: Optional[bytes] = None) -> str:
    """
    Decrypt a JSON bundle produced by encrypt_value and return the original UTF-8 string.

    Args:
        enc_bundle_json: JSON string with fields salt_b64, nonce_b64, ct_b64, label, alg, kdf.
        aad: Optional associated data; must match what was used during encryption.
        key: Optional raw AES key override (bytes). If provided, HKDF derivation is skipped.

    Returns:
        str: decrypted plaintext
    """
    try:
        bundle = json.loads(enc_bundle_json)
        if bundle.get("alg") != "AESGCM" or bundle.get("kdf") != "HKDF-SHA256":
            raise ValueError("Unsupported alg/kdf in bundle")

        label = bundle["label"]
        salt = b64decode(bundle["salt_b64"])
        nonce = b64decode(bundle["nonce_b64"])
        ct = b64decode(bundle["ct_b64"])
    except (KeyError, ValueError, binascii.Error, json.JSONDecodeError) as e:
        raise ValueError("Invalid encryption bundle") from e

    # If caller supplied an explicit AES key, use it; else re-derive from (label, salt)
    if key is None:
        key = derive_key(label, salt=salt, length=32)

    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt.decode("utf-8")



##PUBLIC KEY ENCRYPTION WITH RSA OAEP AND SIGNING WITH RSA PSS##
# -------- helpers --------
SCHEME_ID = "RSA-OAEP(SHA-256)+RSA-PSS(SHA-256)"
SIG_CTX = b"letta-signed-rsa-oaep-v1"

def _b64(x: bytes) -> str: return b64encode(x).decode("ascii")
def _b64d(s: str) -> bytes: return b64decode(s.encode("ascii"))

def _sha256(x: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(x)
    return h.finalize()

def _to_sign(aad_hash: bytes, ct: bytes) -> bytes:
    # Minimal, canonical layout for the signed message
    return b"|".join([SIG_CTX, SCHEME_ID.encode(), aad_hash, ct])

def _load_pub(pem: bytes | str):
    if isinstance(pem, str): pem = pem.encode()
    return serialization.load_pem_public_key(pem)

def _load_priv(pem: bytes | str, password: Optional[bytes] = None):
    if isinstance(pem, str): pem = pem.encode()
    return serialization.load_pem_private_key(pem, password=password)

# -------- API --------
def generate_rsa_keypair(
    key_size: int = 2048,
    password: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Generate an RSA keypair suitable for OAEP+PSS.

    Args:
        key_size: modulus size in bits (2048, 3072, 4096).
        password: optional password (bytes) to encrypt the private key PEM.

    Returns:
        (private_pem_bytes, public_pem_bytes)
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()

    if password:
        encryption_alg = serialization.BestAvailableEncryption(password)
    else:
        encryption_alg = serialization.NoEncryption()

    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg,
    )

    public_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem

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

# def get_key(agentid, keystoreID):
#     client = get_client()
#     keystoreBlock = client.blocks.retrieve(keystoreID) #get keystore block

#     current_value = keystoreBlock.get("value", {})

#     return current_value[agentid]

def get_key(agentid, keystoreID):
    client = get_client()
    keystoreBlock = client.blocks.retrieve(keystoreID)
    raw = getattr(keystoreBlock, "value", None)
    if not raw:
        raise ValueError("Keystore block has no value")
    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("Keystore block value is not valid JSON")
    if agentid not in mapping:
        raise KeyError(f"No key for agent {agentid} in keystore")
    return mapping[agentid]



###ACTUAL TOOLS###
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
        label=f"{label}",
        entity_id=label,
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

    # Return JSON-serializable data (avoid returning SDK objects)
    return {
        "memory_block_id": getattr(memory_block, "id", None),
        "info_block_id": getattr(info_block, "id", None),
    }

from typing import Optional

def read_memory(info_bloc_or_id: str, key: Optional[bytes] = None, aad: bytes | None = None) -> str:
    """
    Retrieve and decrypt a memory block's plaintext content from encrypted storage.

    Args:
        info_bloc_or_id: The *ID string* of the info block to read.
        key: Optional symmetric key override for decryption (bytes). If not provided,
             decrypt_value will re-derive the key from the bundle's salt/label.
        aad: Optional Additional Authenticated Data bytes used during encryption.

    Returns:
        The decrypted plaintext contained in the referenced content block.
    """
    client = get_client()

    # 1) Fetch the info block by its ID
    info_block = client.blocks.retrieve(info_bloc_or_id)

    # 2) Decrypt the info block's value to learn the content block ID
    enc_info = getattr(info_block, "value", None)
    if enc_info is None and isinstance(info_block, dict):
        enc_info = info_block.get("value")
    if enc_info is None:
        raise ValueError("Info block has no 'value' to decrypt")

    try:
        info_plain = decrypt_value(enc_info, key=key, aad=aad)
    except TypeError:
        # Backward-compat if decrypt_value doesn't accept key=
        info_plain = decrypt_value(enc_info, aad=aad)

    try:
        info_obj = json.loads(info_plain)
    except json.JSONDecodeError as e:
        raise ValueError("Info block plaintext is not JSON; expected a 'Memory Block ID' field") from e

    content_block_id = info_obj["Memory Block ID"]

    # 3) Fetch & decrypt the content block
    content_block = client.blocks.retrieve(content_block_id)
    enc_content = getattr(content_block, "value", None)
    if enc_content is None and isinstance(content_block, dict):
        enc_content = content_block.get("value")
    if enc_content is None:
        raise ValueError("Content block has no 'value' to decrypt")

    try:
        content_plain = decrypt_value(enc_content, key=key, aad=aad)
    except TypeError:
        content_plain = decrypt_value(enc_content, aad=aad)

    return content_plain


def retrieve_memory(recipient_agent: object, sender_agent_id: str, ciphertext_one: str, ciphertext_two: str, keystoreID: str):
    """
    Retrieve and reconstruct a shared memory from another agent using RSA-based hybrid decryption.

    This function is the recipient-side counterpart to `share_memory()`.
    It verifies and decrypts two RSA-OAEP/PSS encrypted payloads sent by the sharer:
      1. `ciphertext_one` → the ID of the info block referencing the shared memory.
      2. `ciphertext_two` → the symmetric key used to decrypt the shared memory’s contents.

    Parameters
    ----------
    recipient_agent : object
        The recipient Letta agent object. Must have an `.id` attribute (string).
    sender_agent_id : str
        The unique ID of the agent who originally shared the memory.
    ciphertext_one : str
        RSA-OAEP/PSS–encrypted JSON bundle containing the info block ID.
    ciphertext_two : str
        RSA-OAEP/PSS–encrypted JSON bundle containing the symmetric key (as UTF-8 string).
    keystoreID : str
        The Letta block ID of the keystore that maps agent IDs to public RSA keys.

    Returns
    -------
    None
        Creates a new Letta memory block for the recipient agent containing the shared plaintext.

    Raises
    ------
    ValueError
        If RSA keys, keystore entries, or environment variables are missing.
    RuntimeError
        If decryption or block creation fails.
    """
    recipient_private_key = os.getenv(f"{recipient_agent.id}-PRIVATE_PEM")
    sender_public_key = get_key(sender_agent_id, keystoreID)

    plaintext_one = rsa_oaep_pss_decrypt(
        bundle_json=ciphertext_one,
        recipient_rsa_priv_pem=recipient_private_key,
        sender_rsapss_pub_pem=sender_public_key,
    )
    plaintext_two = rsa_oaep_pss_decrypt(
        bundle_json=ciphertext_two,
        recipient_rsa_priv_pem=recipient_private_key,
        sender_rsapss_pub_pem=sender_public_key,
    )

    info_block_id = plaintext_one
    random_key = plaintext_two.encode()

    memory_block_content = read_memory(info_block_or_id=info_block_id, key=random_key)

    create_memory_block(
        agentid=recipient_agent.id,
        label=memory_block_content[:20],  # use first 20 chars as label
        value=memory_block_content,
        description=f"shared memory from {sender_agent_id}",
    )

    

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

def _extract_text(resp) -> str:
    for m in reversed(resp.messages):
        if hasattr(m, "content") and isinstance(m.content, str):
            return m.content
        out = getattr(m, "output", None) or getattr(m, "result", None)
        if out is not None:
            return out if isinstance(out, str) else json.dumps(out)
    return ""

# def send_message(agent_id: str, content: str) -> str:
#     client = get_client()
#     resp = client.agents.messages.create(
#         agent_id=agent_id,
#         messages=[{"role": "user", "content": content}],
#     )
#     return _extract_text(resp)


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
    # print(response)
    return _extract_text(response)


# --- WRAPPERS (exported as tools) ---

def create_memory_block_tool(agent_id: str, label: str, value: str, description: str) -> dict:
    """
    Create an encrypted memory block and attach its info block to an agent.

    Args:
        agent_id (str): Target agent's ID (e.g., "agent-1234abcd").
        label (str): Human-readable label for the new memory (e.g., "profile", "notes").
        value (str): Plaintext content to encrypt and store in the memory block.
        description (str): Short description to store alongside the memory (for operators).

    Returns:
        dict: JSON-serializable payload with created IDs:
            {
              "memory_block_id": "<block-id>",
              "info_block_id": "<block-id>"
            }

    Raises:
        ValueError: If agent_id/label/value/description are empty.
        RuntimeError: If the Letta API fails to create or attach blocks.
    """
    if not (agent_id and label and value and description):
        raise ValueError("agent_id, label, value, and description are required")
    out = create_memory_block(agent_id, label, value, description)
    return {"memory_block_id": out["memory_block_id"], "info_block_id": out["info_block_id"]}


def read_memory_tool(info_block_id: str, key_hex: str | None = None, aad_b64: str | None = None) -> str:
    """
    Read & decrypt a memory via its info-block ID.

    Args:
        info_block_id (str): The ID of the *info* block that points to the actual content block.
        key_hex (str | None): Optional hex-encoded AES key override (e.g., "a3f2...").
                              If omitted, the key is HKDF-derived from the stored bundle.
        aad_b64 (str | None): Optional base64-encoded AAD used at encryption time.
                              Must match exactly to decrypt successfully.

    Returns:
        str: The decrypted plaintext stored in the referenced content block.

    Raises:
        ValueError: If the info block or content block is missing/invalid, or AAD mismatches.
        RuntimeError: If the Letta API fails to retrieve blocks.
    """
    key = bytes.fromhex(key_hex) if key_hex else None
    aad = b64decode(aad_b64) if aad_b64 else None
    return read_memory(info_block_id, key=key, aad=aad)


def retrieve_memory_tool(
    recipient_agent_id: str,
    sender_agent_id: str,
    ciphertext_one: str,
    ciphertext_two: str,
    keystore_id: str
) -> str:
    """
    Import a memory shared by another agent using RSA-OAEP+PSS bundles.

    Args:
        recipient_agent_id (str): The agent ID that will receive/import the shared memory.
        sender_agent_id (str): The agent ID of the original sharer (used to fetch their public key).
        ciphertext_one (str): JSON bundle (string) produced by rsa_oaep_pss_encrypt
                              holding the *info block ID* (base64 fields inside).
        ciphertext_two (str): JSON bundle (string) produced by rsa_oaep_pss_encrypt
                              holding the *symmetric key* (as UTF-8 string inside).
        keystore_id (str): Block ID of the keystore mapping agent IDs → RSA public keys.

    Returns:
        str: "ok" on success (the function creates a new memory for the recipient).

    Raises:
        ValueError: If keys are missing/invalid, signatures fail, or AAD mismatches.
        RuntimeError: If Letta API calls fail while creating/attaching the new memory.
    """
    client = get_client()
    recipient = client.agents.retrieve(recipient_agent_id)
    retrieve_memory(recipient, sender_agent_id, ciphertext_one, ciphertext_two, keystore_id)
    return "ok"


def ring_an_agent_tool(target_agent_id: str, message: str) -> str:
    """
    Send an agent→agent message.

    Args:
        target_agent_id (str): The destination agent's ID.
        message (str): The text message to post as a user role to the target agent.

    Returns:
        str: A stringified Letta API response (useful for debugging).

    Raises:
        RuntimeError: If the message cannot be delivered via the Letta API.
    """
    if not (target_agent_id and message):
        raise ValueError("target_agent_id and message are required")
    return ring_an_agent(target_agent_id, message)


def send_message_tool(agent_id: str, content: str) -> str:
    """
    Send a user message to an agent and return the agent’s textual reply.

    Args:
        agent_id (str): Target agent ID to send the message to.
        content (str): The text content of the user message.

    Returns:
        str: The assistant's latest textual response (best-effort extraction).
             If the last entry is a tool return, a JSON string of the tool output is returned.

    Raises:
        RuntimeError: If the message send fails or no textual content is extractable.
    """
    if not (agent_id and content):
        raise ValueError("agent_id and content are required")
    return send_message(agent_id, content)


def list_blocks_tool(agent_id: str) -> list[dict]:
    """
    List blocks attached to an agent.

    Args:
        agent_id (str): The agent ID whose attached blocks will be listed.

    Returns:
        list[dict]: A list of { "id": str | None, "label": str | None } for each attached block.

    Raises:
        RuntimeError: If the agent cannot be retrieved.
    """
    client = get_client()
    ag = client.agents.retrieve(agent_id)
    blocks = getattr(ag, "blocks", []) or []
    return [{"id": getattr(b, "id", None), "label": getattr(b, "label", None)} for b in blocks]

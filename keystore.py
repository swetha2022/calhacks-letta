from tooling import get_client

def create_keystore(): #just a block
    client = get_client()
    keystore = client.blocks.create(
        label="Keystore",
        description="Keystore storing all public keys for every user",
        value="",
    )
    return keystore
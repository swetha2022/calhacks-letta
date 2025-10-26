# import os, binascii
# print(binascii.hexlify(os.urandom(32)).decode())
from tooling import get_client


from letta_client import Letta
from letta_client.core.api_error import ApiError

client = get_client()  # uses LETTA_API_KEY from your env

def delete_all_identities():
    try:
        # 1. List all identities (the SDK paginates automatically if needed)
        identities = client.identities.list()
        print(f"Found {len(identities)} identities")

        # 2. Delete them one by one
        for ident in identities:
            ident_id = getattr(ident, "id", None)
            if not ident_id:
                continue
            print(f"Deleting {ident_id} ...")
            try:
                client.identities.delete(ident_id)
            except ApiError as e:
                print(f"  ⚠️ Failed to delete {ident_id}: {e}")

        print("✅ Finished deleting all identities.")

    except ApiError as e:
        print(f"Error while listing identities: {e}")

delete_all_identities()

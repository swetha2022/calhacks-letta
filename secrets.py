from tooling import get_client

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

# delete_all_identities()


def delete_all_agents():
    try:
        agents = client.agents.list()
        print(f"Found {len(agents)} agents")

        for agent in agents:
            agent_id = getattr(agent, "id", None)
            if not agent_id:
                continue
            print(f"Deleting {agent_id} ...")
            try:
                client.agents.delete(agent_id)
            except ApiError as e:
                print(f"  ⚠️ Failed to delete {agent_id}: {e}")

        print("✅ Finished deleting all agents.")

    except ApiError as e:
        print(f"Error while listing agents: {e}")


def delete_agent(agent_id: str):
    try:
        client.agents.delete(agent_id)
        print(f"Deleted agent {agent_id}")
    except ApiError as e:
        print(f"  ⚠️ Failed to delete {agent_id}: {e}")
delete_all_agents()



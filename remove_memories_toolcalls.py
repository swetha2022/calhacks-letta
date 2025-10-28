import re

# names of *your* tools you actually want the agent to be able to call
ALLOW = {
    "ring_an_agent",
    "send_to_agent",
    "msg_send_agent",
    "roll_die",
    # optional read-only utilities (safe):
    # "read_memory", "list_blocks",
}

# anything that looks like it edits memory (reject)
FORBID_RE = re.compile(r"(^memory_|create_?mem(or(y|ies))|share_?mem(or(y|ies))|replace_?mem)", re.I)

def toolid(tool_obj):
    # adapt to your SDK’s shape; tool_obj may be dict or pydantic model
    return getattr(tool_obj, "id", tool_obj["id"])

def toolname(tool_obj):
    return getattr(tool_obj, "name", tool_obj["name"])

# Suppose you already created/loaded your tools into `all_my_tools`
# Filter to the ones allowed and not forbidden by name pattern.
safe_tools = [
    t for t in all_my_tools
    if toolname(t) in ALLOW and not FORBID_RE.search(toolname(t))
]

allowed_tool_ids = [toolid(t) for t in safe_tools]

# sanity check
assert allowed_tool_ids, "No tools selected—did you build ALLOW correctly?"

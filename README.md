# Secure, Shareable Memory Blocks for Agents
**TLDR: Letta lets agents create, share, and read memory blocks with explicit, cryptographically‑enforced permissions**

Agents are powerful—but without guardrails they can leak, overcollect, or misuse data. Letta gives your agents a principled memory model: every piece of remembered data sits in a memory block with an owner, a policy, and a cryptographic identity. Owners can share blocks with specific users/agents; readers can only access what they’re permitted to see.


Most agent “memory” today is just a database row indexed by a user id. That’s convenient—and dangerous.

# Security impact at a glance

Least privilege by design — Agents fetch only blocks they’re permitted to read; nothing else is even addressable.

Owner‑controlled sharing — Memory is private by default. Sharing is explicit, auditable, and revocable.

Tamper‑evident history — Every create, share, and read is written to an audit log to support investigations and compliance.

Strong crypto boundaries — Blocks are encrypted at rest; wrapped keys enable per‑recipient access without re‑encrypting data.

Safer agent‑to‑agent collaboration — Clear permissions reduce accidental exfiltration across tools, chains, or teams.

Compliance‑friendly — Data minimization, scoped access, and deletion flows help you meet GDPR/SOC 2 style controls (no certification claims).


# Core concepts

**Memory Block**: The atomic unit of memory (payload + metadata). Has an owner, a policy, and a block id.

**Owner**: The user/agent that created the block; only owners can grant or revoke access.

**Permissions**:

*read*: view and decrypt the block

*write*: update/append (optional, if you enable mutable blocks)

*share*: grant/revoke others’ access

*Policy*: Constraints (e.g., recipients, roles, TTL/expiry, tags, sensitivity).

*Audit Log*: Append‑only events for create/share/read/revoke.

This repository includes modules like letta.py, keystore.py, crypto.py, and tooling.py, which implement the agent orchestration, key management, cryptographic helpers, and development utilities respectively.
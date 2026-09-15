---
name: Identity migrations
description: Rules for adding required account identity data to an existing BloxdVids user base.
---

New account requirements such as email should be enforced at registration and login without inventing values for legacy accounts. Keep legacy fields nullable until the owner has a verified backfill path.

**Why:** Existing BloxdVids accounts were created before email became part of authentication, so fabricated addresses would create ownership and recovery risks.

**How to apply:** Validate and normalize the field for new registrations, use case-insensitive uniqueness, and keep legacy users usable until an explicit verified migration flow exists.
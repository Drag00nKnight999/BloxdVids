---
name: App Storage bucket IDs
description: Selecting the correct Replit App Storage bucket for server-side uploads.
---

Use the App Storage **Bucket ID** shown in the editor's App Storage settings when creating the Replit Object Storage `Client`. Do not assume the bucket's display label is a valid ID. For this app, provide it through the shared `REPLIT_OBJECT_STORAGE_BUCKET` environment variable.

**Why:** Passing a human-facing label as the Google Cloud bucket identifier can fail validation even though the bucket exists in App Storage.

**How to apply:** When storage reports an invalid or missing bucket, verify the configured Bucket ID in App Storage settings and the shared environment variable. Never substitute the display name without confirming it matches the SDK's required ID.
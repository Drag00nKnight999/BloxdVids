# BloxdVids

BloxdVids is a video-sharing web application built with Node.js, Express, and PostgreSQL. It supports video uploads and playback, user channels, comments, likes, subscriptions, and moderation tools.

## Features

- User accounts, channel pages, and video discovery
- Video upload, playback, thumbnails, and metadata
- Comments, likes, and channel subscriptions
- User reports, account appeals, and moderator review
- Copyright notice and counter-notice intake with a private moderator queue
- Administrative tools for account and content moderation

## Requirements

- Node.js (a current LTS release is recommended)
- PostgreSQL
- Replit App Storage configured for video and thumbnail files

## Configuration

Set these environment variables through your hosting platform's secrets/environment configuration. Do not commit credentials or populated environment files:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string |
| `SESSION_SECRET` | Secret used to sign session cookies |
| `OWNER_PASSWORD` | Initial owner account password |
| `REPLIT_OBJECT_STORAGE_BUCKET` | Replit App Storage Bucket ID |

The application will not start without `DATABASE_URL`, `SESSION_SECRET`, `OWNER_PASSWORD`, and a valid `REPLIT_OBJECT_STORAGE_BUCKET`. Keep their values private. In Replit, use the App Storage **Bucket ID**, not its display label.

## Run locally

1. Create a PostgreSQL database and configure the required environment variables.
2. Configure object storage and set its bucket ID as described above.
3. Install dependencies:

   ```sh
   npm install
   ```

4. Start the server:

   ```sh
   npm start
   ```

The server listens on port `5000` by default and uses the `PORT` environment variable when provided. Database tables are initialized when the server starts.

## Copyright intake

The public DMCA page collects copyright notices and counter-notices and returns a submission reference. Moderators and administrators can review submissions in the moderation center. The intake flow does not automatically remove or restore content and does not establish that the service has registered or published a designated agent. The public page explains this limitation.

## Legal notice

This repository and its public legal pages provide general information, not legal advice. Consult a qualified attorney for legal matters. Do not treat the presence of an intake form as confirmation of legal compliance.
# XBOST v8

Production build of the XBOST business simulator.

## Render

Run as a **Web Service**, not a Static Site.

- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`
- Health check: `/api/health`

Required environment variables:

- `DATABASE_URL` — Render Postgres connection string
- `SESSION_SECRET` — long random secret
- `PLAYER_PASSWORD_HASH` — scrypt hash generated outside the repository
- `FOUNDER_PASSWORD_HASH` — scrypt hash generated outside the repository
- `NODE_ENV=production`

Passwords are never stored in the public HTML or the Git repository.

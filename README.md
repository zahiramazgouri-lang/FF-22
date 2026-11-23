# LEGACY 22 — Cloudflare Backend Starter

Independent backend starter for the original LEGACY 22 game project. It is not connected to Garena or Free Fire.

## Included
- Cloudflare Worker API
- Cloudflare D1 SQL schema
- Register/login with PBKDF2 password hashing and signed JWTs
- Player profile endpoint
- Owner-only currency grant endpoint
- Audit log for owner actions

## Deploy overview
1. Create a Cloudflare D1 database named `legacy22-db`.
2. In D1, run the SQL in `schema.sql`.
3. Create a Worker named `legacy22-api` and upload/deploy this project using the Cloudflare dashboard's Workers editor, or connect a GitHub repository.
4. Bind the D1 database to the Worker with binding name `DB`.
5. Add Worker secrets `JWT_SECRET` and `OWNER_SECRET` (use long, random values; never put them in GitHub).
6. Set `wrangler.toml` database `database_id` to the ID shown by Cloudflare.

This is a starter, not a production-ready anti-cheat or game server. Before public launch, add rate limiting, email/account recovery, abuse monitoring, backups, and server-authoritative match validation.

# Rebel Ink Tattoos

Simple Render Web Service deploy (same style as HairInk).

## Deploy

1. Push this folder to GitHub (files at repo root).
2. Render → New → Web Service
3. Build: leave empty (or `echo ok`)
4. Start: `node server.js`
5. Deploy — no environment variables required.

## Admin access

Use the private admin email and password you were given.
They are NOT displayed on the website.

Sign in via the site: **Admin** button → enter your credentials.

## Health

GET /api/health

## Optional env vars

JWT_SECRET and ADMIN_SETUP_TOKEN — set in Render Environment if you want them stable across restarts.

# Examples Directory

This directory contains real-world configurations and deployment recipes for `caddy-warden`.

## Scenarios

- [**Basic Protection (`examples/basic/Caddyfile`)**](basic/Caddyfile)
  - Default sensitive asset rules (.env, .git, database dumps, cloud credentials).
  - Custom path pattern rules.
  - IP and CIDR allowlisting.
  - Query parameter inspection.
  - JSON 403 response with custom security headers.

- [**Interactive Captcha Challenge (`examples/captcha/Caddyfile`)**](captcha/Caddyfile)
  - Intercept scanner bots and challenge human visitors using Cloudflare Turnstile, hCaptcha, or Google reCAPTCHA.

- [**Aggressive Bot Defense & Scanner Tarpits (`examples/aggressive-defense/Caddyfile`)**](aggressive-defense/Caddyfile)
  - `tarpit`: Delays byte delivery (e.g. 1000ms per byte) to exhaust bot connection pools.
  - `gzipBomb`: Returns highly compressed zero-byte payloads to induce decompressor memory exhaustion on automated scrapers.
  - `infiniteStream`: Streams unending randomized pseudorandom data chunks.
  - `silentDrop`: Abruptly terminates TCP socket without sending any HTTP headers.

- [**Honeypot Decoys, Proxying & Rate Limiting (`examples/honeypot-and-redirect/Caddyfile`)**](honeypot-and-redirect/Caddyfile)
  - `redirect`: Diverts offending requests to an external analysis honeypot or sinkhole.
  - `proxy`: Transparently forwards blocked requests to an isolated honeypot container backend.
  - `rateLimitChallenge`: Returns HTTP 429 with `Retry-After` backoff headers.

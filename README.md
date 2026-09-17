# RouteWarden for Caddy (`caddy-warden`)

High-performance Caddy v2 middleware module to stop sensitive file exposure (`.env`, `.git`, backups), neutralize path-evasion attacks, whitelist IPs, and serve custom error/captcha responses before requests reach your upstream backend.

[![CI](https://github.com/routewarden/caddy-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/routewarden/caddy-warden/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🚀 Installation

Build Caddy with RouteWarden using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build \
    --with github.com/routewarden/caddy-warden
```

---

## ⚡ Quickstart (`Caddyfile`)

Register the directive order in your global options block, then place `routewarden` in any site:

```caddyfile
{
    order routewarden first
}

example.com {
    routewarden {
        # Optional: custom regex patterns to guard
        path_patterns (?i)^/admin/(secrets|internal)(/.*)?$

        # Whitelist safe patterns
        allow_patterns (?i)^/api/internal/health$

        # Whitelist corporate VPN / Office IPs
        allowed_ips 10.0.0.0/8 192.168.1.100

        # Response configuration
        response {
            mode json
            status 403
            body '{"error":"Forbidden","message":"Access to sensitive endpoint is blocked"}'
        }
    }

    reverse_proxy localhost:8080
}
```

---

## 🛡️ Key Features

- **Anti-Probing & Scanner Defense**: Intercepts automated bots probing for `.env`, `.git`, `phpinfo.php`, `.aws/credentials`, database dumps (`.sql`, `.bak`, `.tar.gz`), and actuator endpoints.
- **Anti-Evasion Engine**: Normalizes multi-layer URL encoding (`%252e%252e`), semicolon matrix parameters (`/;param/.env`), Windows backslashes (`\`), and null bytes before regex matching.
- **IP & CIDR Subnet Whitelisting**: Bypass checks for trusted office IPs or VPN subnets (`allowed_ips 10.0.0.0/8`).
- **13 Multi-Action Response Modes**:
  - `json` / `html` / `text` / `xml`
  - `captcha` (Cloudflare Turnstile, hCaptcha, Google reCAPTCHA)
  - `redirect` (deflect to honeypot)
  - `silentDrop` (instantly close connection)
  - `gzipBomb` (force memory exhaustion on automated scrapers)
  - `tarpit` (slow trickling connection sink)
  - `fakeSuccess` (synthetic honeypot payload)
  - `rateLimitChallenge` (HTTP 429 backoff header)
  - `infiniteStream` (pseudo-random endless stream)

---

## ⚙️ Caddyfile Directives Reference

```caddyfile
routewarden {
    # Disable entire plugin
    disable

    # Disable out-of-the-box sensitive dictionaries (.env, .git, etc.)
    disable_default_patterns

    # Disable default allowlist (robots.txt, sitemap.xml, .well-known)
    disable_default_allow_patterns

    # Inspect query parameters for sensitive filenames
    check_query

    # Custom block patterns (regex)
    path_patterns <regex...>

    # Custom safe allow patterns (regex)
    allow_patterns <regex...>

    # Allowed client IPs or CIDR subnets
    allowed_ips <ip/cidr...>

    # Custom response engine
    response {
        mode <json|html|text|captcha|redirect|silentDrop|gzipBomb|tarpit|fakeSuccess|rateLimitChallenge|proxy|infiniteStream|xml>
        status <int>
        content_type <string>
        body <string>
        redirect_url <string>
        proxy_url <string>
        gzip_bomb_mb <int>
        retry_after <int>
        tarpit_delay_ms <int>
        tarpit_max_duration <int>
        stream_size_mb <int>
        header <name> <value>
        captcha <provider> <site_key> [title]
    }
}
```

---

## 🧪 Testing & Verification

```bash
# Run unit & anti-evasion tests with race detection
go test -v -race ./...
```

---

## License

MIT License. Copyright © 2026 RouteWarden Contributors.

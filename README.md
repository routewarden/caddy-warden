<div align="center">
  <img src="assets/icon.svg" alt="RouteWarden Logo" width="140" height="140" />
  <h1>RouteWarden for Caddy</h1>
  <p><strong>High-performance Caddy v2 middleware module to stop sensitive file exposure (.env, .git, backups, database dumps, cloud credentials), neutralize path-evasion attacks, whitelist IPs, and serve custom error/captcha/honeypot responses before requests reach your upstream backend.</strong></p>
</div>

<p align="center">
  <a href="https://github.com/routewarden/caddy-warden/actions/workflows/ci.yml"><img src="https://github.com/routewarden/caddy-warden/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
  <a href="https://github.com/routewarden/caddy-warden"><img src="https://img.shields.io/badge/Coverage-95.9%25-brightgreen.svg" alt="Coverage" /></a>
  <a href="https://goreportcard.com/report/github.com/routewarden/caddy-warden"><img src="https://goreportcard.com/badge/github.com/routewarden/caddy-warden" alt="Go Report Card" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="https://routewarden.github.io/docs/"><img src="https://img.shields.io/badge/Docs-VitePress%20Wiki-6366f1.svg" alt="Documentation Site" /></a>
</p>

---

> 📖 **Full Documentation, Guides & Wiki**: [https://routewarden.github.io/docs/](https://routewarden.github.io/docs/)  
> 📂 **Runnable Scenarios**: [`examples/`](examples/) *(Caddyfile configurations)*

---

## 🚀 Installation

RouteWarden is a Caddy v2 plugin and must be compiled into Caddy using `xcaddy` or built via Docker.

### Option 1: Using `xcaddy` (CLI)

Install [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
# macOS (Homebrew)
brew install xcaddy

# Debian / Ubuntu / Linux
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-xcaddy-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-xcaddy.list
sudo apt update && sudo apt install xcaddy

# Or with Go
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

Build Caddy with RouteWarden (pin to a specific release tag or use `@latest`):

```bash
# Pin to a specific release (Recommended for production stability)
xcaddy build \
    --with github.com/routewarden/caddy-warden@v0.2.4

# Or build against the latest release
xcaddy build \
    --with github.com/routewarden/caddy-warden
```

Verify the module is registered:

```bash
./caddy list-modules | grep routewarden
# Output: http.handlers.routewarden
```

---

### Option 2: Docker Multi-Stage Build

Use the official `caddy:builder` image to build a customized Caddy binary with pinned `caddy-warden`:

```dockerfile
# Dockerfile
FROM caddy:2.9-builder AS builder

# Pin to a specific version with @vX.Y.Z
RUN xcaddy build \
    --with github.com/routewarden/caddy-warden@v0.2.4

FROM caddy:2.9-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

Build and run:

```bash
docker build -t caddy-warden .
docker run -d -p 80:80 -p 443:443 -v $PWD/Caddyfile:/etc/caddy/Caddyfile caddy-warden
```

---

### Option 3: Docker Compose

```yaml
# docker-compose.yml
services:
  caddy:
    build:
      context: .
      dockerfile: Dockerfile
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config

volumes:
  caddy_data:
  caddy_config:
```

---

### Option 4: Custom Go Application / Embedding

Import RouteWarden into your custom Caddy build script or Go project:

```bash
# Pin to a specific version
go get github.com/routewarden/caddy-warden@v0.2.4

# Or latest
go get github.com/routewarden/caddy-warden@latest
```

Import blank identifier to trigger auto-registration:

```go
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/routewarden/caddy-warden"
)

func main() {
	caddycmd.Main()
}
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

        # HTTP methods to inspect (default: GET)
        methods GET POST

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

- **Anti-Probing & Scanner Defense**: Intercepts automated bots probing for `.env`, `.git`, `phpinfo.php`, `.aws/credentials`, `.kube/config`, database dumps (`.sql`, `.bak`, `.tar.gz`), package manager lockfiles, and Spring Boot Actuator endpoints.
- **Anti-Evasion Engine**: Normalizes multi-layer URL encoding (`%252e%252e`), semicolon matrix parameters (`/;param/.env`), Windows backslashes (`\..\.env`), and null bytes before regex matching.
- **IP & CIDR Subnet Whitelisting**: Bypass checks for trusted office IPs or VPN subnets (`allowed_ips 10.0.0.0/8 192.168.1.100`).
- **Query Parameter Inspection**: Detect probes passed via query parameters (`check_query` checks `?file=.env` and decoded equivalents).
- **13 Multi-Action Response Modes**:
  - `json` / `html` / `text` / `xml`
  - `captcha` (Cloudflare Turnstile, hCaptcha, Google reCAPTCHA)
  - `redirect` (deflect to honeypot or sinkhole)
  - `silentDrop` (instantly close TCP connection)
  - `gzipBomb` (force memory exhaustion on automated scrapers)
  - `tarpit` (slow trickling connection sink)
  - `fakeSuccess` (synthetic honeypot payload)
  - `rateLimitChallenge` (HTTP 429 backoff header)
  - `infiniteStream` (pseudo-random endless stream)
  - `proxy` (transparent honeypot reverse proxy)

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

    # HTTP methods to inspect (default: GET)
    methods <GET|POST|PUT|DELETE...>

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

## 📁 Examples

Check out the [`examples/`](examples) directory for complete, ready-to-run configurations:

- [**Basic Protection**](examples/basic/Caddyfile): Default blocklists, custom pattern protection, CIDR whitelist, and JSON 403 response.
- [**Captcha Challenge**](examples/captcha/Caddyfile): Deflect automated bots with Cloudflare Turnstile verification.
- [**Aggressive Defense**](examples/aggressive-defense/Caddyfile): Tarpits, memory-exhausting gzip bombs, infinite random streams, and silent drops.
- [**Honeypot & Redirection**](examples/honeypot-and-redirect/Caddyfile): Redirecting to external traps, reverse-proxying into honeypot containers, and rate-limit challenges.

---

## 🧪 Testing & Verification

RouteWarden is tested against real-world path evasion attacks, evasion matrices, and scanner evasion techniques with **>95% test coverage**:

```bash
# Run unit & anti-evasion tests with race detection
go test -v -race ./...

# Run test coverage profiling
go test -v -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

---

## 🏷️ Versioning

RouteWarden follows [Semantic Versioning 2.0.0](https://semver.org/). See [VERSIONING.md](VERSIONING.md) for release workflows, policies, and version update script documentation.

---

## 📄 License

MIT License. Copyright © 2026 RouteWarden Contributors.

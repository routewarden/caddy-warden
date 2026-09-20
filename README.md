<div align="center">
  <img src="assets/icon.svg" alt="RouteWarden Logo" width="140" height="140" />
  <h1>RouteWarden for Caddy</h1>
  <p>A Caddy v2 plugin that blocks scanners from finding sensitive files (.env, .git, backups, database dumps, cloud credentials) and handles path-evasion tricks before requests hit your backend.</p>
</div>

<p align="center">
  <a href="https://github.com/routewarden/caddy-warden/actions/workflows/ci.yml"><img src="https://github.com/routewarden/caddy-warden/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
  <a href="https://github.com/routewarden/caddy-warden"><img src="https://img.shields.io/badge/Coverage-98.8%25-brightgreen.svg" alt="Coverage" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="https://routewarden.github.io/docs/"><img src="https://img.shields.io/badge/Docs-Wiki-6366f1.svg" alt="Documentation Site" /></a>
</p>

---

- **Live Playground**: [Try RouteWarden in your browser](https://routewarden.github.io/docs/?playground=open)
- **Documentation & Guides**: [https://routewarden.github.io/docs/](https://routewarden.github.io/docs/)
- **Example Configurations**: [`examples/`](examples/)

---

## Why RouteWarden?

Web servers constantly receive automated requests searching for exposed secrets, such as `.env` files, `.git` directories, database backups, and private keys. Attackers often hide these probes using URL encoding, backslashes, or path traversal tricks to bypass basic path filters.

RouteWarden sits directly inside Caddy to catch these requests early. It cleans and decodes the requested path, checks it against known sensitive patterns or your own custom rules, and responds immediately before your application ever sees the request.

---

## Installation

Because RouteWarden is a Caddy module, it needs to be built into Caddy using `xcaddy` or Docker.

### Option 1: Build with `xcaddy` (CLI)

First, install [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
# macOS
brew install xcaddy

# Debian / Ubuntu / Linux
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-xcaddy-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-xcaddy.list
sudo apt update && sudo apt install xcaddy

# Or using Go
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

Then build Caddy with RouteWarden:

```bash
# Pin to a specific version (recommended for production)
xcaddy build \
    --with github.com/routewarden/caddy-warden@v1.0.0

# Or build using the latest version
xcaddy build \
    --with github.com/routewarden/caddy-warden
```

Confirm that the module is installed:

```bash
./caddy list-modules | grep routewarden
# Output: http.handlers.routewarden
```

---

### Option 2: Build with Docker

Use Caddy's official multi-stage builder to create your image:

```dockerfile
# Dockerfile
FROM caddy:2.9-builder AS builder

RUN xcaddy build \
    --with github.com/routewarden/caddy-warden@v1.0.0

FROM caddy:2.9-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

Build and run the container:

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

### Option 4: Custom Go Build

If you build your own Caddy binary in Go, import RouteWarden for automatic registration:

```bash
go get github.com/routewarden/caddy-warden@v1.0.0
```

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

## Quickstart

Add `order routewarden first` to your global options block, then configure `routewarden` inside your site definition:

```caddyfile
{
    order routewarden first
}

example.com {
    routewarden {
        # Custom regex patterns you want to block
        path_patterns (?i)^/admin/(secrets|internal)(/.*)?$

        # Patterns that should always be allowed
        allow_patterns (?i)^/api/internal/health$

        # Whitelist trusted IP addresses or subnets (e.g., office VPN)
        allowed_ips 10.0.0.0/8 192.168.1.100

        # HTTP methods to inspect (defaults to GET)
        methods GET POST

        # What to return when a request is blocked
        response {
            mode json
            status 403
            body "{\"error\":\"Forbidden\",\"message\":\"Access to sensitive endpoint is blocked\"}"
        }
    }

    reverse_proxy localhost:8080
}
```

---

## What It Does

- **Blocks Probes and Scanners**: Automatically blocks requests for sensitive files including `.env`, `.git`, `phpinfo.php`, `.aws/credentials`, `.kube/config`, SQL dumps, backups (`.bak`, `.tar.gz`), and actuator endpoints.
- **Normalizes Evasive Paths**: Decodes multiple layers of URL encoding (`%252e%252e`), strips matrix parameters (`/;param/.env`), converts backslashes, and strips null bytes so scanners cannot slip past filters.
- **IP Allowlisting**: Exempt trusted corporate IPs, office networks, or VPN subnets from being blocked.
- **Query Parameter Checks**: Optionally inspect query parameters (like `?file=.env`) when `check_query` is enabled.
- **Flexible Response Modes**: Choose how to answer blocked requests:
  - Standard errors: `json`, `html`, `text`, or `xml`
  - Bot verification: `captcha` (Cloudflare Turnstile, hCaptcha, Google reCAPTCHA)
  - Deflection: `redirect` to a honeypot or sinkhole, or `proxy` to an isolated backend
  - Aggressive bot handling: `silentDrop` (close connection immediately), `tarpit` (trickle bytes slowly), `gzipBomb` (exhaust bot memory), `infiniteStream`, `fakeSuccess`, or `rateLimitChallenge` (HTTP 429)

---

## Caddyfile Reference

```caddyfile
routewarden {
    # Turn off RouteWarden for this site
    disable

    # Turn off default sensitive file patterns (.env, .git, etc.)
    disable_default_patterns

    # Turn off default safe list (robots.txt, sitemap.xml, .well-known)
    disable_default_allow_patterns

    # Check query strings for sensitive filenames
    check_query

    # Enable verbose debug logs (evaluations, candidate paths, IP matching)
    debug

    # Emit structured CrowdSec / SIEM security audit logs on block
    security_log

    # Custom regex patterns to block
    path_patterns <regex...>

    # Custom regex patterns to allow
    allow_patterns <regex...>

    # Trusted client IPs or CIDR subnets
    allowed_ips <ip/cidr...>

    # HTTP methods to inspect (default: GET)
    methods <GET|POST|PUT|DELETE...>

    # Response behavior
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

## CLI & Config Generation

You can use the official [`rwarden`](https://routewarden.github.io/cli/) CLI tool to test path rules offline, validate configurations, and automatically generate Caddyfile directive blocks directly from a unified `routewarden.json` schema:

```bash
# Install RouteWarden CLI
curl -fsSL https://routewarden.github.io/cli/install.sh | bash

# Or run via Docker
docker run --rm ghcr.io/routewarden/cli:latest version
```

### Generating Caddyfile Directives:

```bash
# Generate Caddyfile routewarden directive block
rwarden generate --target caddy --config routewarden.json

# Test a suspicious probe path against rules offline
rwarden test --path "/.env"
```

For complete documentation on the CLI, installation methods, and options, visit the **[RouteWarden CLI Documentation](https://routewarden.github.io/cli/)**.

---

## Documentation & Integrations

For complete guides, configuration references, and integration recipes, visit the official documentation:

- [**RouteWarden Documentation**](https://routewarden.github.io/docs)
- [**CrowdSec Integration & Auto-Ban Guide**](https://routewarden.github.io/docs/examples/crowdsec): Detect and ban aggressive scanners automatically using CrowdSec.
- [**Response Modes & Defense Actions**](https://routewarden.github.io/docs/reference/response-modes)
- [**Anti-Evasion Engine**](https://routewarden.github.io/docs/reference/anti-evasion)

---

## Examples

Ready-to-use Caddyfiles are available in the [`examples/`](examples) directory:

- [**Basic Protection**](examples/basic/Caddyfile): Built-in blocklists, custom patterns, IP whitelisting, and JSON 403 responses.
- [**Captcha Challenge**](examples/captcha/Caddyfile): Verify suspected bot traffic using Cloudflare Turnstile.
- [**Aggressive Defense**](examples/aggressive-defense/Caddyfile): Slow down or deter scrapers with tarpits, gzip bombs, infinite streams, or silent drops.
- [**Honeypot & Redirection**](examples/honeypot-and-redirect/Caddyfile): Redirect probes to an external sinkhole, forward to an isolated honeypot container, or return rate-limit challenges.

---

## Testing

RouteWarden has full automated tests for path normalization, pattern matching, and response modes, with over 98% test coverage:

```bash
# Run tests with race detection
go test -v -race ./...

# View coverage summary
go test -v -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

---

## Versioning

RouteWarden uses [Semantic Versioning 2.0.0](https://semver.org/). For release procedures and version management details, see [VERSIONING.md](VERSIONING.md).

---

## License

MIT License. Copyright (c) 2026 RouteWarden Contributors.

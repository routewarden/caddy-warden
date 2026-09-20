# RouteWarden Samples & Live Testing Environment

This directory provides a multi-port Docker Compose environment and an automated test suite (`test.sh`) to verify all RouteWarden response modes, security flags, path-evasion protections, and IP filtering capabilities.

## Architecture

The test environment provisions:
1. **Caddy Container**: Builds Caddy with the local RouteWarden module directly from source code (`samples/Dockerfile`) and exposes 15 dedicated test ports mapped in `samples/Caddyfile`.
2. **Honeypot Backend Container**: A lightweight Python HTTP server on port `9999` to verify `mode proxy` (transparent honeypot redirection).

---

## Directory Layout

```
samples/
├── Caddyfile            # Multi-port Caddy configuration exercising all modes and flags
├── Dockerfile           # Builds Caddy with RouteWarden from the repo root
├── docker-compose.yml   # Multi-container orchestration (Caddy + Honeypot)
├── test.sh              # Bash verification script testing each port and scenario
└── README.md            # Documentation and instructions
```

---

## Port Mappings & Features Tested

| Port | Mode / Feature | Verification Scenario |
| :--- | :--- | :--- |
| **8080** | Core & JSON | Built-in sensitive files (`.env`, `.git`, SQL dumps, actuator endpoints, `.aws` credentials, `package-lock.json`, TLS `.key`/`.pem`, `docker-compose.yml`, `.DS_Store`, `wp-config.php`); anti-evasion traversal (`%252e%252e`), matrix parameters (`/;param`); `check_query`; IP allowlist bypass via `allowed_ips`; `allow_patterns` overrides. |
| **8081** | `html` | Returns custom HTML error page with `text/html` headers. |
| **8082** | `text` | Returns plain text message with `text/plain` headers. |
| **8083** | `xml` | Returns structured `<Error>` XML document. |
| **8084** | `captcha` | Serves security challenge page with Cloudflare Turnstile markup. |
| **8085** | `redirect` | Emits HTTP 302 redirect with `Location` header to honeypot sinkhole. |
| **8086** | `rateLimitChallenge` | Emits HTTP 429 status code with `Retry-After: 180` header. |
| **8087** | `fakeSuccess` | Returns synthetic decoy credentials (`.env`, git HEAD, actuator). |
| **8088** | `gzipBomb` | Emits compressed gzip stream with `Content-Encoding: gzip`. |
| **8089** | `silentDrop` | Abruptly terminates TCP socket connection upon probe. |
| **8090** | `infiniteStream` | Streams continuous garbage data chunks to exhaust automated parsers. |
| **8091** | `proxy` | Transparently reverse-proxies blocked probes to honeypot backend container. |
| **8092** | `disable` | Flag verification: RouteWarden disabled, all requests pass through to upstream. |
| **8093** | `methods` | Verb filter verification: Only inspects `POST` & `DELETE`; `GET` bypasses filter. |
| **8094** | `check_headers` | Header inspection: Blocks requests where `X-Forwarded-Uri` or `X-Rewrite-URL` header contains a sensitive path (e.g. `/.env`, `/.git`). |

---

## Running the Live Tests

### 1. Start the Environment

From the repository root:

```bash
docker compose -f samples/docker-compose.yml up --build -d
```

### 2. Execute the Test Suite

```bash
./samples/test.sh
```

### 3. Teardown

```bash
docker compose -f samples/docker-compose.yml down -v
```

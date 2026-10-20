# Build Caddy with RouteWarden module
FROM caddy:2.9-builder AS builder

WORKDIR /src
COPY . .

# Build Caddy binary with local module source
RUN xcaddy build \
    --with github.com/routewarden/caddy-warden=.

# Final minimal runtime image based on official Caddy Alpine
FROM caddy:2.9-alpine

LABEL org.opencontainers.image.title="Caddy Warden"
LABEL org.opencontainers.image.description="Official Caddy v2 with RouteWarden active security and threat mitigation module"
LABEL org.opencontainers.image.url="https://github.com/routewarden/caddy-warden"
LABEL org.opencontainers.image.source="https://github.com/routewarden/caddy-warden"
LABEL org.opencontainers.image.vendor="RouteWarden"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

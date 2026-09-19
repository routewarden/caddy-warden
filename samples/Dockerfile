# Build stage: compile Caddy with local caddy-warden module
FROM caddy:2.11.4-builder AS builder

WORKDIR /src
# Copy local module files
COPY . .

# Build Caddy with the local caddy-warden module
RUN xcaddy build \
    --with github.com/routewarden/caddy-warden=.

# Runtime stage
FROM caddy:2.11.4-alpine

COPY --from=builder /src/caddy /usr/bin/caddy
COPY samples/Caddyfile /etc/caddy/Caddyfile

EXPOSE 8080 8081 8082 8083 8084 8085 8086 8087 8088 8089 8090 8091 8092 8093

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

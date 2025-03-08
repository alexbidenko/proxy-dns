FROM caddy:2-alpine

RUN adduser --system --uid 1001 caddy

RUN mkdir -p /data/caddy \
    mkdir -p config \
    chown -R caddy:caddy /data/caddy \
    chown -R caddy:caddy /config

COPY --chown=caddy:caddy Caddyfile /etc/caddy

USER caddy

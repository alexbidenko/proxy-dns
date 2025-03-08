FROM caddy:2-alpine

RUN addgroup -g 1001 -S caddy && \
    adduser -u 1001 -G caddy -S -H -s /sbin/nologin caddy

RUN mkdir -p /data/caddy && \
    mkdir -p /config && \
    chown -R caddy:caddy /data/caddy && \
    chown -R caddy:caddy /config

COPY --chown=caddy:caddy Caddyfile /etc/caddy

USER caddy

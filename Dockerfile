# Build the UI and bundle the Express/worker entry point.
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run lint && npm test && npm run build

# Runtime includes only the server dependencies and required scanner binaries.
FROM node:22-bookworm-slim AS runtime
ARG TARGETARCH
ENV NODE_ENV=production \
    PORT=3000 \
    PROOFVAPT_DATA_DIR=/data \
    HOME=/tmp \
    TMPDIR=/tmp \
    JAVA_TOOL_OPTIONS="-Xms64m -Xmx768m"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openjdk-17-jre-headless tar \
    && rm -rf /var/lib/apt/lists/*

# Pin ffuf 2.3.0 by architecture and verify the upstream release checksum.
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) ffuf_sha="b2a3c725fcb9da175159682f54d6e9149f2905b00d84d155e7efc5d599975ceb" ;; \
      arm64) ffuf_sha="e2d712615d53da797ee929006e41f2df5a7960a5353133db9c150ddaa22ae4e8" ;; \
      *) echo "Unsupported TARGETARCH for ffuf: $TARGETARCH"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_${TARGETARCH}.tar.gz" -o /tmp/ffuf.tar.gz; \
    echo "$ffuf_sha  /tmp/ffuf.tar.gz" | sha256sum -c -; \
    mkdir -p /tmp/ffuf; \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp/ffuf; \
    install -m 0755 "$(find /tmp/ffuf -type f -name ffuf -print -quit)" /usr/local/bin/ffuf; \
    rm -rf /tmp/ffuf /tmp/ffuf.tar.gz

# Pin OWASP ZAP 2.17.0 and verify the official release checksum.
RUN set -eux; \
    curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz" -o /tmp/zap.tar.gz; \
    echo "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a  /tmp/zap.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/zap.tar.gz -C /opt; \
    test -x /opt/ZAP_2.17.0/zap.sh; \
    ln -s /opt/ZAP_2.17.0/zap.sh /usr/local/bin/zap.sh; \
    rm -f /tmp/zap.tar.gz

WORKDIR /app
COPY --from=build --chown=node:node /app/package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/dist-server ./dist-server
COPY --from=build --chown=node:node /app/server/wordlists ./server/wordlists
RUN mkdir -p /data/artifacts && chown -R node:node /data
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node", "/app/dist-server/server.js"]

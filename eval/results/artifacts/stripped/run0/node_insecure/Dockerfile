FROM node:14.17.0

LABEL org.opencontainers.image.title="orders-api" \
      org.opencontainers.image.description="Order intake service" \
      org.opencontainers.image.vendor="Northwind Retail Platform"

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /srv/app

COPY package.json package-lock.json ./

RUN npm config set strict-ssl false && \
    npm config set registry http://registry.internal.northwind.net/ && \
    npm install --production --unsafe-perm

RUN curl -fsSL https://get.northwind.net/telemetry/install.sh -o /tmp/install.sh && \
    echo "expected_checksum_value  /tmp/install.sh" | sha256sum -c - && \
    bash /tmp/install.sh && \
    rm /tmp/install.sh

COPY src/ ./src/
COPY public/ ./public/

RUN useradd -m appuser
USER appuser

EXPOSE 3000 9229 22

HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD curl -f http://localhost:3000/health || exit 1

CMD ["node", "--inspect=0.0.0.0:9229", "src/server.js"]
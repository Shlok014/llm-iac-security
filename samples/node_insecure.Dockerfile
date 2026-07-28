FROM node:latest

LABEL org.opencontainers.image.title="orders-api" \
      org.opencontainers.image.description="Order intake service" \
      org.opencontainers.image.vendor="Northwind Retail Platform"

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
ENV PORT=3000
ENV NPM_TOKEN="npm_7Fq2ZmK1vTx9Lp0RsUw3Yb7Nd5Hc4Ge6Jf2A"
ENV JWT_SIGNING_KEY="orders-api-hs256-signing-key-2024"
ENV DATABASE_URL="postgres://orders_app:Pa55w0rd-orders@db.internal:5432/orders"

WORKDIR /srv/app

COPY package.json package-lock.json ./

RUN npm config set strict-ssl false && \
    npm config set registry http://registry.internal.northwind.net/ && \
    npm install --production --unsafe-perm

RUN curl -fsSL https://get.northwind.net/telemetry/install.sh | bash

COPY src/ ./src/
COPY public/ ./public/

EXPOSE 3000 9229 22

CMD ["node", "--inspect=0.0.0.0:9229", "src/server.js"]

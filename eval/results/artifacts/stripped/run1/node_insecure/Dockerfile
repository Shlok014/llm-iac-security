FROM node:14.17.0

LABEL org.opencontainers.image.title="orders-api" \
      org.opencontainers.image.description="Order intake service" \
      org.opencontainers.image.vendor="Northwind Retail Platform"

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
ENV PORT=3000

# Use build arguments for sensitive information
ARG NPM_TOKEN
ARG JWT_SIGNING_KEY
ARG DATABASE_URL

WORKDIR /srv/app

COPY package.json package-lock.json ./

RUN npm config set strict-ssl false && \
    npm config set registry http://registry.internal.northwind.net/ && \
    npm install --production --unsafe-perm

# Download and verify the script before executing
RUN curl -fsSL https://get.northwind.net/telemetry/install.sh -o install.sh && \
    echo "expected_checksum_value  install.sh" | sha256sum -c - && \
    bash install.sh && \
    rm install.sh

COPY src/ ./src/
COPY public/ ./public/

EXPOSE 3000 9229 22

# Create a non-root user and switch to it
RUN useradd -m appuser
USER appuser

# Add a HEALTHCHECK instruction
HEALTHCHECK CMD curl --fail http://localhost:3000/health || exit 1

CMD ["node", "--inspect=0.0.0.0:9229", "src/server.js"]
# vulnerable.Dockerfile  -- FOR TESTING ONLY (do NOT use in production)

# 1) Floating base tag (non-reproducible, may include CVEs)
FROM python:3.10.12-slim

# 2) Running as root by default (no USER set later)
# 3) Install a bunch of packages (unneeded attack surface) and leave cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget git && \
    rm -rf /var/lib/apt/lists/*

# 4) Copy a secrets file from build context (simulates accidental secret bake-in)
# Removed COPY instruction for secrets

# 5) ADD remote archive (unsafe: will download and unpack remote content)
# Replaced ADD with a safer method
RUN curl -fsSL https://example.com/tools/toolkit.tar.gz -o /tmp/toolkit.tar.gz && \
    tar -xzf /tmp/toolkit.tar.gz -C /tmp/remote-tool/ && \
    rm /tmp/toolkit.tar.gz

# 6) Copy whole context (danger: may include host secrets) and install python deps without hashes
COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# 7) Expose unnecessary/privileged ports (e.g. docker daemon or SSH)
EXPOSE 5000

# 8) Embed credentials as ENV (visible via docker inspect)
# Removed ENV instructions for sensitive information

# 9) Writable directory with world-write permissions
RUN mkdir -p /app/data && chmod 755 /app/data

# 10) Execute remote install script directly (curl | sh) — remote code execution risk
# Downloading and verifying the script before execution
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh && \
    sh /tmp/install.sh && \
    rm /tmp/install.sh

# 11) Start sshd (unnecessary service inside container)
# Removed SSH server installation and related commands

# 12) Create a SUID-like binary (simulated privileged file)
# Removed creation of SUID-like binary

# 13) No healthcheck, no non-root user, no minimal base image
# Added a non-root user and a HEALTHCHECK instruction
RUN useradd -m appuser
USER appuser

HEALTHCHECK CMD curl --fail http://localhost:5000/ || exit 1

CMD ["/bin/bash"]
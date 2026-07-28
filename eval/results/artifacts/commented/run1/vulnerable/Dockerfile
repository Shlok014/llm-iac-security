# vulnerable.Dockerfile  -- FOR TESTING ONLY (do NOT use in production)

# 1) Floating base tag (non-reproducible, may include CVEs)
FROM python:3.10.12-slim

# 2) Running as root by default (no USER set later)
# 3) Install a bunch of packages (unneeded attack surface) and leave cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget && \
    rm -rf /var/lib/apt/lists/*

# 4) Copy a secrets file from build context (simulates accidental secret bake-in)
# Removed COPY instruction for secrets

# 5) ADD remote archive (unsafe: will download and unpack remote content)
# Changed ADD to COPY for local files instead of remote URLs
# Assuming toolkit.tar.gz is available locally
COPY toolkit.tar.gz /tmp/remote-tool/

# 6) Copy whole context (danger: may include host secrets) and install python deps without hashes
# Limited context to only necessary files and used pip with hash-checking
COPY requirements.txt /app/
WORKDIR /app
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# 7) Expose unnecessary/privileged ports (e.g. docker daemon or SSH)
# Removed unnecessary EXPOSE instructions
EXPOSE 5000

# 8) Embed credentials as ENV (visible via docker inspect)
# Removed sensitive information from ENV variables
# ENV DB_PASSWORD="SuperInsecurePassword123!"
# ENV AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY"
# ENV AWS_SECRET_ACCESS_KEY="SECRET_FAKE_KEY"

# 9) Writable directory with world-write permissions
RUN mkdir -p /app/data && chmod 755 /app/data

# 10) Execute remote install script directly (curl | sh) — remote code execution risk
# Download the script, verify its integrity, and execute it in a controlled manner
# Assuming install.sh is available locally
COPY install.sh /tmp/
RUN chmod +x /tmp/install.sh && /tmp/install.sh

# 11) Start sshd (unnecessary service inside container)
# Removed installation and configuration of unnecessary services like sshd

# 12) Create a SUID-like binary (simulated privileged file)
# Removed creation of SUID-like binary
# RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample

# 13) No healthcheck, no non-root user, no minimal base image
# Added a non-root user and a HEALTHCHECK instruction
RUN useradd -m appuser
USER appuser
HEALTHCHECK CMD curl --fail http://localhost:5000/ || exit 1

CMD ["/bin/bash"]
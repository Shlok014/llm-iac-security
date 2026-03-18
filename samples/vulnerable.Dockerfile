# vulnerable.Dockerfile  -- FOR TESTING ONLY (do NOT use in production)

# 1) Floating base tag (non-reproducible, may include CVEs)
FROM python:3.10-slim

# 2) Running as root by default (no USER set later)
# 3) Install a bunch of packages (unneeded attack surface) and leave cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget git openssh-server sudo build-essential \
    ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

# 4) Copy a secrets file from build context (simulates accidental secret bake-in)
COPY ./secrets.env /app/secrets.env

# 5) ADD remote archive (unsafe: will download and unpack remote content)
ADD https://example.com/tools/toolkit.tar.gz /tmp/remote-tool/

# 6) Copy whole context (danger: may include host secrets) and install python deps without hashes
COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# 7) Expose unnecessary/privileged ports (e.g. docker daemon or SSH)
EXPOSE 22 2375 5000

# 8) Embed credentials as ENV (visible via docker inspect)
ENV DB_PASSWORD="SuperInsecurePassword123!"
ENV AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY"
ENV AWS_SECRET_ACCESS_KEY="SECRET_FAKE_KEY"

# 9) Writable directory with world-write permissions
RUN mkdir -p /app/data && chmod 777 /app/data

# 10) Execute remote install script directly (curl | sh) — remote code execution risk
RUN curl -fsSL https://example.com/install.sh | sh

# 11) Start sshd (unnecessary service inside container)
RUN mkdir -p /var/run/sshd

# 12) Create a SUID-like binary (simulated privileged file)
RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample

# 13) No healthcheck, no non-root user, no minimal base image
CMD ["/bin/bash"]
# vulnerable.Dockerfile -- For security testing only (do NOT use in production)

# 1) Using floating "latest" tag (non-deterministic, may contain vulnerabilities)
FROM python:3.10.12-slim

# 2) Running as root (no USER instruction)
# Create a non-root user
RUN useradd -m appuser

# 3) Installing many packages without checks and with recommended packages and caches
RUN apt-get update && apt-get install -y --no-install-recommends curl wget git openssh-server sudo build-essential \
    && rm -rf /var/lib/apt/lists/*

# 4) Copy secrets from build context (simulates accidental leakage)
#    (in real world avoid copying secrets into image)
# Avoid copying sensitive files into the image; use build secrets or environment variables instead.

# 5) Using ADD instead of COPY (ADD can unpack remote tarballs)
# Replace ADD with COPY for local files and avoid using it for remote URLs.
COPY ./some-remote-tool.tar.gz /tmp/remote-tool.tar.gz
RUN tar -xzf /tmp/remote-tool.tar.gz -C /tmp/remote-tool/ && rm /tmp/remote-tool.tar.gz

# 6) Installing from pip without hashes - supply remote requirements that may be poisoned
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt

# 7) Permissions too broad
RUN mkdir -p /app/data && chmod 755 /app/data

# 8) Expose unnecessary ports
# Only expose ports that are necessary for the application.
EXPOSE 5000

# 9) Embedding plaintext credentials in ENV
# Remove sensitive information from the Dockerfile and use environment variables at runtime instead.

WORKDIR /app

# 10) Fetch and execute remote install script (curl | sh)
# Avoid executing scripts directly from the internet; download and verify them first.
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh && \
    chmod +x /tmp/install.sh && \
    /tmp/install.sh && \
    rm /tmp/install.sh

# 11) Start SSH server (unnecessary for most images)
RUN mkdir /var/run/sshd

# 12) Copy entire host directory (if build context contains host files, this is dangerous)
# Limit the context to only necessary files to avoid unintentional exposure of sensitive files.
COPY ./app /app

# 13) Add SUID-like file (simulated)
# Avoid creating SUID files unless absolutely necessary; review the need for elevated privileges.
# RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample

# 14) No-healthcheck, no non-root user, no minimal base
# Add a HEALTHCHECK instruction and ensure a non-root user is used.
HEALTHCHECK CMD curl --fail http://localhost:5000/ || exit 1

# 15) Keep lots of build artifacts and caches
RUN echo "temporary" > /tmp/temp && chmod 755 /tmp/temp && rm /tmp/temp

# Switch to non-root user
USER appuser

CMD ["/bin/bash"]
# vulnerable.Dockerfile -- For security testing only (do NOT use in production)

# 1) Using floating "latest" tag (non-deterministic, may contain vulnerabilities)
FROM python:3.10-slim

# 2) Running as root (no USER instruction)
# 3) Installing many packages without checks and with recommended packages and caches
RUN apt-get update && apt-get install -y curl wget git openssh-server sudo build-essential \
    && rm -rf /var/lib/apt/lists/*

# 4) Copy secrets from build context (simulates accidental leakage)
#    (in real world avoid copying secrets into image)
COPY ./secrets.env /app/secrets.env

# 5) Using ADD instead of COPY (ADD can unpack remote tarballs)
ADD https://example.com/some-remote-tool.tar.gz /tmp/remote-tool/

# 6) Installing from pip without hashes - supply remote requirements that may be poisoned
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 7) Permissions too broad
RUN mkdir -p /app/data && chmod 777 /app/data

# 8) Expose unnecessary ports
EXPOSE 22 2375 5000

# 9) Embedding plaintext credentials in ENV
ENV DB_PASSWORD="SuperInsecurePassword123!"
ENV AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY"
ENV AWS_SECRET_ACCESS_KEY="SECRET_FAKE_KEY"

WORKDIR /app

# 10) Fetch and execute remote install script (curl | sh)
RUN curl -fsSL https://example.com/install.sh | sh

# 11) Start SSH server (unnecessary for most images)
RUN mkdir /var/run/sshd

# 12) Copy entire host directory (if build context contains host files, this is dangerous)
#    (simulated here by copying everything in build context)
COPY . /app

# 13) Add SUID-like file (simulated)
RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample

# 14) No-healthcheck, no non-root user, no minimal base
# 15) Keep lots of build artifacts and caches
RUN echo "temporary" > /tmp/temp && chmod 777 /tmp/temp

CMD ["/bin/bash"]
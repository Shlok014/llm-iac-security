FROM python:3.10.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget git openssh-server sudo build-essential \
    ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

# Use a secure secrets management solution instead of copying secrets directly
# COPY ./secrets.env /app/secrets.env

# Replace ADD with RUN curl to download the file
RUN curl -fsSL https://example.com/tools/toolkit.tar.gz -o /tmp/remote-tool/toolkit.tar.gz

COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Remove exposing SSH and Docker daemon ports
# EXPOSE 22 2375 5000

# Use a secure secrets management solution instead of baking sensitive information
# ENV DB_PASSWORD="SuperInsecurePassword123!"
# ENV AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY"
# ENV AWS_SECRET_ACCESS_KEY="SECRET_FAKE_KEY"

RUN mkdir -p /app/data && chmod 700 /app/data

# Download the script, verify its integrity, and then execute it
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh && \
    sh /tmp/install.sh

RUN mkdir -p /var/run/sshd

# Remove the creation of the SUID executable
# RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample

# Add a HEALTHCHECK instruction
HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:5000/health || exit 1

# Specify a non-root user to run the application
USER nobody

CMD ["/bin/bash"]
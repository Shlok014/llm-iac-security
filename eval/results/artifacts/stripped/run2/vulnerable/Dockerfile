FROM python:3.10.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget git openssh-server sudo build-essential \
    ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

# Use a secrets management tool or mount secrets at runtime instead of copying them into the image
# COPY ./secrets.env /app/secrets.env

RUN curl -fsSL https://example.com/tools/toolkit.tar.gz -o /tmp/remote-tool/toolkit.tar.gz && \
    mkdir -p /tmp/remote-tool && \
    tar -xzf /tmp/remote-tool/toolkit.tar.gz -C /tmp/remote-tool && \
    rm /tmp/remote-tool/toolkit.tar.gz

COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Exposing SSH and Docker daemon ports without proper security measures
# EXPOSE 22 2375
EXPOSE 5000

# Use a secrets management tool or environment variables at runtime instead of baking sensitive information
# ENV DB_PASSWORD="SuperInsecurePassword123!"
# ENV AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY"
# ENV AWS_SECRET_ACCESS_KEY="SECRET_FAKE_KEY"

RUN mkdir -p /app/data && chmod 700 /app/data

# Download the script, verify its integrity, and then execute it
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh && \
    sh /tmp/install.sh && \
    rm /tmp/install.sh

RUN mkdir -p /var/run/sshd

# Removed the creation of SUID executables
# RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample

# Specify a non-root user to run the application
RUN useradd -ms /bin/bash appuser
USER appuser

# Add a HEALTHCHECK instruction to monitor the health of the running container
HEALTHCHECK CMD curl --fail http://localhost:5000/health || exit 1

CMD ["/bin/bash"]
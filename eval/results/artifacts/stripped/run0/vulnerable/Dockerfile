FROM python:3.10.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget git openssh-server sudo build-essential \
    ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

# Avoid copying sensitive files into the image; use environment variables or a secrets management solution.
# COPY ./secrets.env /app/secrets.env

# Replace ADD with RUN curl to download files, and ensure the source is trusted.
RUN curl -fsSL https://example.com/tools/toolkit.tar.gz -o /tmp/remote-tool/toolkit.tar.gz

COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Remove the EXPOSE instruction for ports that are not needed or secure them with proper authentication.
# EXPOSE 22 2375 5000

# Use a secrets management tool instead of baking sensitive information into the image.
# ENV DB_PASSWORD="SuperInsecurePassword123!"
# ENV AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY"
# ENV AWS_SECRET_ACCESS_KEY="SECRET_FAKE_KEY"

RUN mkdir -p /app/data && chmod 700 /app/data

# Download the script, verify its integrity (e.g., checksum), and then execute it.
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh && \
    sh /tmp/install.sh

RUN mkdir -p /var/run/sshd

# Remove the creation of SUID executables unless absolutely necessary and justified.
# RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample

# Specify a non-root user to run the application using the USER instruction.
USER nobody

# Add a HEALTHCHECK instruction to periodically check the health of the application.
HEALTHCHECK CMD curl --fail http://localhost:5000/health || exit 1

CMD ["/bin/bash"]
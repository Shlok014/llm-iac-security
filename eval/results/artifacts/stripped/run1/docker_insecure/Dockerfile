FROM python:3.10.12-slim

RUN apt-get update && apt-get install -y curl wget git \
    && rm -rf /var/lib/apt/lists/*

# Secrets should not be baked into the image. Use environment variables or a secrets management tool instead.
# COPY ./secrets.env /app/secrets.env

# Using ADD to fetch remote files can introduce risks. Ensure the remote source is trusted.
# ADD https://example.com/some-remote-tool.tar.gz /tmp/remote-tool/

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN mkdir -p /app/data && chmod 755 /app/data

# Exposing ports without security measures can lead to unauthorized access. Consider removing unnecessary ports.
# EXPOSE 22 2375 5000

# Use a secure secrets management solution to handle sensitive information instead of hardcoding it.
# ENV DB_PASSWORD="SuperInsecurePassword123!"
# ENV AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY"
# ENV AWS_SECRET_ACCESS_KEY="SECRET_FAKE_KEY"

WORKDIR /app

RUN curl -fsSL https://example.com/install.sh | sh

RUN mkdir /var/run/sshd

COPY . /app

# Avoid creating SUID executables unless absolutely necessary.
# RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample

# Set more restrictive permissions for temporary files.
RUN echo "temporary" > /tmp/temp && chmod 600 /tmp/temp

# Adding a HEALTHCHECK instruction to monitor the health of the application.
HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:5000/ || exit 1

# Create a non-root user and switch to that user.
RUN useradd -m appuser
USER appuser

CMD ["/bin/bash"]
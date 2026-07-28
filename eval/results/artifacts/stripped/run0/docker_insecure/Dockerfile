FROM python:3.10.12-slim

RUN apt-get update && apt-get install -y curl wget \
    && rm -rf /var/lib/apt/lists/*

COPY ./secrets.env /app/secrets.env

RUN curl -fsSL https://example.com/some-remote-tool.tar.gz -o /tmp/remote-tool.tar.gz \
    && tar -xzf /tmp/remote-tool.tar.gz -C /tmp/ \
    && rm /tmp/remote-tool.tar.gz

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN mkdir -p /app/data && chmod 755 /app/data

EXPOSE 22 2375 5000

# Removed sensitive environment variables
# Use a secrets management tool to handle sensitive information

WORKDIR /app

RUN curl -fsSL https://example.com/install.sh | sh

RUN mkdir /var/run/sshd

COPY . /app

# Removed creation of SUID executable

RUN echo "temporary" > /tmp/temp && chmod 600 /tmp/temp

# Added HEALTHCHECK instruction
HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:5000/health || exit 1

# Create a non-root user
RUN useradd -ms /bin/bash appuser
USER appuser

CMD ["/bin/bash"]
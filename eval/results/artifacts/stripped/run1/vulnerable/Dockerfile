FROM python:3.10.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget git openssh-server sudo build-essential \
    ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

COPY ./secrets.env /app/secrets.env

RUN curl -fsSL https://example.com/tools/toolkit.tar.gz -o /tmp/remote-tool/toolkit.tar.gz && \
    tar -xzf /tmp/remote-tool/toolkit.tar.gz -C /tmp/remote-tool/ && \
    rm /tmp/remote-tool/toolkit.tar.gz

COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 2375 5000

RUN mkdir -p /app/data && chmod 755 /app/data

RUN mkdir -p /var/run/sshd

HEALTHCHECK CMD curl --fail http://localhost:5000/health || exit 1

RUN useradd -m appuser
USER appuser

CMD ["/bin/bash"]
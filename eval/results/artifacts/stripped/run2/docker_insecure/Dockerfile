FROM python:3.10.12-slim

RUN apt-get update && apt-get install -y curl wget git \
    && rm -rf /var/lib/apt/lists/*

COPY ./secrets.env /app/secrets.env

RUN curl -fsSL https://example.com/some-remote-tool.tar.gz -o /tmp/remote-tool.tar.gz \
    && tar -xzf /tmp/remote-tool.tar.gz -C /tmp/ \
    && rm /tmp/remote-tool.tar.gz

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN mkdir -p /app/data && chmod 755 /app/data

EXPOSE 22 2375 5000

WORKDIR /app

RUN curl -fsSL https://example.com/install.sh | sh

RUN mkdir /var/run/sshd

COPY . /app

HEALTHCHECK CMD curl --fail http://localhost:5000/ || exit 1

USER appuser

CMD ["/bin/bash"]
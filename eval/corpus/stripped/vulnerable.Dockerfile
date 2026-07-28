


FROM python:3.10-slim



RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget git openssh-server sudo build-essential \
    ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*


COPY ./secrets.env /app/secrets.env


ADD https://example.com/tools/toolkit.tar.gz /tmp/remote-tool/


COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt


EXPOSE 22 2375 5000


ENV DB_PASSWORD="SuperInsecurePassword123!"
ENV AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY"
ENV AWS_SECRET_ACCESS_KEY="SECRET_FAKE_KEY"


RUN mkdir -p /app/data && chmod 777 /app/data


RUN curl -fsSL https://example.com/install.sh | sh


RUN mkdir -p /var/run/sshd


RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample


CMD ["/bin/bash"]
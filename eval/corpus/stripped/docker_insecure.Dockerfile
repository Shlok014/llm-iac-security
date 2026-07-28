


FROM python:3.10-slim



RUN apt-get update && apt-get install -y curl wget git openssh-server sudo build-essential \
    && rm -rf /var/lib/apt/lists/*



COPY ./secrets.env /app/secrets.env


ADD https://example.com/some-remote-tool.tar.gz /tmp/remote-tool/


COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt


RUN mkdir -p /app/data && chmod 777 /app/data


EXPOSE 22 2375 5000


ENV DB_PASSWORD="SuperInsecurePassword123!"
ENV AWS_ACCESS_KEY_ID="AKIA_FAKE_KEY"
ENV AWS_SECRET_ACCESS_KEY="SECRET_FAKE_KEY"

WORKDIR /app


RUN curl -fsSL https://example.com/install.sh | sh


RUN mkdir /var/run/sshd



COPY . /app


RUN touch /usr/local/bin/suid_sample && chmod 4755 /usr/local/bin/suid_sample



RUN echo "temporary" > /tmp/temp && chmod 777 /tmp/temp

CMD ["/bin/bash"]
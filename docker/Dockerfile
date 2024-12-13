FROM python:3.12-alpine3.21

COPY . /app
WORKDIR /app/

RUN mkdir -p /opt/tosca-templates/

RUN apk add --no-cache git && \
    git clone https://github.com/grycap/tosca/ && \
    cd tosca && \
    cp templates/* /opt/tosca-templates/ && \
    rm -rf tosca && \
    apk del git

ENV PYTHONPATH=/app

RUN apk add --no-cache mariadb-dev
RUN apk add --no-cache --virtual build-deps gcc python3-dev musl-dev
RUN pip3 install --no-cache-dir gunicorn==23.0.0 && pip3 install --no-cache-dir -r /app/requirements.txt
RUN apk del build-deps

EXPOSE 5001

ENV WORKER_TYPE="sync"
ENV TIMEOUT=180
ENV ENABLE_HTTPS=False
ENV WORKERS=4
ENV THREADS=1

COPY ./docker/start.sh /start.sh

CMD ["/bin/sh","/start.sh"]

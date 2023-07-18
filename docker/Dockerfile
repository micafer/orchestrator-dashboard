FROM python:3.10-alpine3.15

COPY . /app
WORKDIR /app/

COPY ./tosca-templates /opt/tosca-templates

ENV PYTHONPATH=/app

RUN apk add --no-cache mariadb-dev
RUN apk add --no-cache --virtual build-deps gcc python3-dev musl-dev
RUN pip3 install --no-cache-dir gunicorn==20.1.0 && pip3 install --no-cache-dir -r /app/requirements.txt
RUN apk del build-deps

EXPOSE 5001

ENV WORKER_TYPE "sync"
ENV TIMEOUT 180
ENV ENABLE_HTTPS False
ENV WORKERS 4
ENV THREADS 1

COPY ./docker/start.sh /start.sh

CMD ["/bin/sh","/start.sh"]

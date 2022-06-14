FROM python:3.10-alpine3.15

RUN apk add --no-cache git

COPY . /app
WORKDIR /app/

COPY ./tosca-templates /opt/tosca-templates

ENV PYTHONPATH=/app

RUN apk add --no-cache --virtual .build-deps gcc libc-dev git libffi-dev openssl-dev\
    && pip3 install gunicorn==20.1.0 && pip3 install -r /app/requirements.txt \
    && apk del .build-deps gcc libc-dev git libffi-dev openssl-dev

EXPOSE 5001

ENV WORKER_TYPE "gthread"
ENV TIMEOUT 180
ENV ENABLE_HTTPS False
ENV WORKERS 4
ENV THREADS 1

COPY ./docker/start.sh /start.sh

CMD ["/bin/sh","/start.sh"]

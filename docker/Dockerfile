FROM python:3.8.6-alpine3.12

RUN apk add --no-cache git

COPY . /app
WORKDIR /app/

COPY ./tosca-templates /opt/tosca-templates

ENV PYTHONPATH=/app

RUN apk add --no-cache --virtual .build-deps gcc libc-dev git \
    && pip3 install meinheld==1.0.2 gunicorn==20.0.4 && pip3 install -r /app/requirements.txt \
    && apk del .build-deps gcc libc-dev git

EXPOSE 5001

ENV WORKER_TYPE "egg:meinheld#gunicorn_worker"
ENV TIMEOUT 180
ENV ENABLE_HTTPS False
ENV WORKERS 4

COPY ./docker/start.sh /start.sh

CMD ["/bin/sh","/start.sh"]




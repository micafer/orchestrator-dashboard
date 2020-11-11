FROM python:3.8

COPY . /app
WORKDIR /app/

COPY ./tosca-templates /opt/tosca-templates

ENV PYTHONPATH=/app

RUN pip3 install gunicorn==20.0.4 && pip install -r /app/requirements.txt

EXPOSE 5001

ENV WORKER_TYPE sync
ENV TIMEOUT 180
ENV ENABLE_HTTPS False
ENV WORKERS 4

COPY ./docker/start.sh /start.sh

CMD ["/bin/bash","/start.sh"]




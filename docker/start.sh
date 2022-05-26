#!/bin/bash



if [ "${ENABLE_HTTPS}" == "True" ]; then
  if test -e /certs/cert.pem && test -f /certs/key.pem ; then
    exec gunicorn --bind 0.0.0.0:5001 -k "$WORKER_TYPE" -w "$WORKERS" --certfile /certs/cert.pem --keyfile /certs/key.pem --timeout "$TIMEOUT"  imdashboard:app
  else
    echo "[ERROR] File /certs/cert.pem or /certs/key.pem NOT FOUND!"
    exit 1
  fi
else
  exec gunicorn --bind 0.0.0.0:5001 -k "$WORKER_TYPE" -w "$WORKERS" --timeout "$TIMEOUT" --threads "$THREADS" imdashboard:app
fi
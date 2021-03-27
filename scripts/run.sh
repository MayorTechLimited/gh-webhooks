#!/bin/sh
set -e

. venv/bin/activate

exec gunicorn \
    --bind 127.0.0.1:5800 \
    --workers 1 \
    wsgi:app

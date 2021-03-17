#!/bin/sh
set -e

. venv/bin/activate

gunicorn \
    --bind 127.0.0.1:5800 \
    wsgi:app

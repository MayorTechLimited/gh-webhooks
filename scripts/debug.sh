#!/bin/sh
set -e

. venv/bin/activate

export FLASK_APP=main.py
export FLASK_ENV=development
flask run

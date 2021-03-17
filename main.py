import hmac
import json
import os
import subprocess
from pathlib import Path

from flask import Flask, abort, jsonify, request

GH_SECRET = os.environ["GH_SECRET"].encode()

app = Flask(__name__)


def check_signature(req):
    header_signature = req.headers.get("X-Hub-Signature")
    if header_signature is None:
        abort(403)

    sha_name, signature = header_signature.split("=")
    if sha_name != "sha1":
        abort(501)

    mac = hmac.new(GH_SECRET, msg=req.data, digestmod="sha1")
    if not hmac.compare_digest(mac.hexdigest(), signature):
        abort(403)


def run_hooks(event, payload):
    repo = payload["repository"]["name"]
    owner = payload["repository"]["owner"]["login"]

    app_dir = Path(".")
    hooks = [
        app_dir / "hooks" / owner / repo / event,
        app_dir / "hooks" / owner / repo / "all",
        app_dir / "hooks" / owner / "all",
        app_dir / "hooks" / "all",
    ]
    hooks = [h for h in hooks if h.is_file()]
    payload = json.dumps(payload).encode()
    for h in hooks:
        p = subprocess.Popen(["nohup", h, event], stdin=subprocess.PIPE)
        p.stdin.write(payload)
        p.stdin.flush()
        p.stdin.close()


@app.route("/", methods=("POST",))
def index():
    check_signature(request)
    event = request.headers.get("X-GitHub-Event", "ping")
    run_hooks(event, request.json)
    return jsonify({"msg": "done"})

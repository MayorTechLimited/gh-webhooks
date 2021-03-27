import hmac
import json
import os
import subprocess
from pathlib import Path

from flask import Flask, abort, jsonify, request
from loguru import logger

GH_SECRET = os.environ["GH_SECRET"].encode()

app = Flask(__name__)
logger.add("main.log", rotation="100 MB", retention="1 week")


@logger.catch
def check_signature(req):
    sig = req.headers.get("X-Hub-Signature")
    logger.bind(signature=sig).info("Checking signature...")

    if sig is None:
        logger.bind(signature=sig).error("No signature!")
        abort(403)

    sha_name, signature = sig.split("=")
    if sha_name != "sha1":
        logger.bind(signature=sig).error("Unsupported signature type!")
        abort(501)

    mac = hmac.new(GH_SECRET, msg=req.data, digestmod="sha1")
    if not hmac.compare_digest(mac.hexdigest(), signature):
        logger.bind(signature=sig).error("Mismatching signatures")
        abort(403)

    logger.bind(signature=sig).info("Signatures match!")


@logger.catch
def run_hooks(event, request):
    payload = request.json
    repo = payload["repository"]["name"]
    owner = payload["repository"]["owner"]["login"]

    logger.bind(repo=repo, owner=owner, event=event).info("Looking for hooks...")

    app_dir = Path(".")
    hooks = [
        app_dir / "hooks" / owner / repo / event,
        app_dir / "hooks" / owner / repo / "all",
        app_dir / "hooks" / owner / "all",
        app_dir / "hooks" / "all",
    ]
    payload = json.dumps(payload).encode()
    hooks = [h for h in hooks if h.is_file()]
    for idx, hook in enumerate(hooks):
        logger.bind(repo=repo, owner=owner, event=event, hook=hook).info("Running hook")
        p = subprocess.Popen(
            ["nohup", hook, event],
            stdin=subprocess.PIPE,
        )
        p.stdin.write(payload)
        p.stdin.flush()
        p.stdin.close()

    logger.bind(repo=repo, owner=owner, event=event).info("All hooks run!")


@app.route("/", methods=("POST",))
def index():
    logger.info("Received webhook...")
    check_signature(request)
    event = request.headers.get("X-GitHub-Event", "ping")
    run_hooks(event, request)
    return jsonify({"msg": "Done"})

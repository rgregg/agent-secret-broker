"""python -m secret_broker --config /data/config.json"""
import argparse
import json
import os
import signal
import threading

from .backends import BwBackend, FileBackend
from .broker import Broker, serve
from . import notify
from .summarize import OpenRouterSummarizer


def _read(path):
    return open(path).read().strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/data/config.json")
    args = ap.parse_args()
    cfg = json.load(open(args.config))

    b = cfg["backend"]
    backend = (BwBackend(b["server_url"], b["master_password_file"],
                         idle_timeout=b.get("idle_timeout", 300))
               if b["type"] == "bw" else FileBackend(b["path"]))
    notifier = notify.build(cfg, _read)
    summarizer = None
    sc = cfg.get("summary")
    if sc:
        summarizer = OpenRouterSummarizer(
            _read(sc["api_key_file"]), sc["model"], timeout=sc.get("timeout", 4.0),
            max_content_chars=sc.get("max_content_chars", 300),
            send_content=sc.get("send_content", True))
    broker = Broker(cfg, backend, notifier, audit=cfg.get("audit_log"), summarizer=summarizer)
    bind = os.environ.get("BIND", "0.0.0.0")
    serve(broker,
          (bind, int(cfg.get("client_port", 8800))),
          (bind, int(cfg.get("approval_port", 8801))),
          _read(cfg["client_key_file"]))
    print("secret-broker listening", flush=True)
    signal.signal(signal.SIGTERM, lambda *a: os._exit(0))
    threading.Event().wait()


if __name__ == "__main__":
    main()

"""python -m secret_broker

Settings come from the BROKER_CONFIG environment variable (a JSON object) and/or
--config FILE (both are merged, the variable wins). They hold only wiring: vault
URL, notify transports, ports, risk threshold. The list of secrets is NOT here:
it is read from the vault (items carrying a `broker` custom field).
"""
import argparse
import json
import os
import signal
import threading

from .backends import BwBackend, BwServeBackend, FileBackend
from .broker import Broker, serve
from . import notify
from .summarize import OpenRouterSummarizer


def _read(path):
    return open(path).read().strip()


def load_settings(config_path=None):
    cfg = {}
    if config_path:
        cfg.update(json.load(open(config_path)))
    if os.environ.get("BROKER_CONFIG"):
        cfg.update(json.loads(os.environ["BROKER_CONFIG"]))
    return cfg


def build_backend(cfg):
    b = cfg["backend"]
    bw_class = BwServeBackend if b.get("serve") else BwBackend
    return (bw_class(b["server_url"], b["master_password_file"],
                     idle_timeout=b.get("idle_timeout", 300),
                     organization=b.get("organization"), collection=b.get("collection"))
            if b["type"] == "bw" else FileBackend(b["path"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = load_settings(args.config)
    if not cfg:
        ap.error("no settings: set BROKER_CONFIG or pass --config")
    backend = build_backend(cfg)
    notify.parse_action_policy(cfg.get("notify_actions"), "notify_actions")   # fail at startup
    if cfg.get("webpush") is not None:
        from .webpush import parse_actions
        parse_actions(cfg["webpush"])       # fail at startup on a bad webpush.actions
    notify.parse_ha_hook(cfg.get("ha_hook"), _read)     # fail at startup, naming the field
    push = None
    if any(sp.get("type") == "webpush" for sp in cfg.get("notify") or []):
        from .webpush import store_from_config
        push = store_from_config(cfg)
    notifier = notify.build(cfg, _read, push_store=push)
    summarizer = None
    sc = cfg.get("summary")
    if sc:
        summarizer = OpenRouterSummarizer(
            _read(sc["api_key_file"]), sc["model"], timeout=sc.get("timeout", 4.0),
            max_content_chars=sc.get("max_content_chars", 300),
            send_content=sc.get("send_content", True))
    broker = Broker(cfg, backend, notifier, audit=cfg.get("audit_log"), summarizer=summarizer,
                    background_load=True, push=push)
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

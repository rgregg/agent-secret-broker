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

from .backends import BackendConfigError, registry
from .broker import Broker, parse_extra_origins, parse_trusted_proxies, serve
from . import destguard, clients, sessions, credreq, grants, notify, plans, presence, proposals, request_details, risk, riskmodel


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
    """The backend named by cfg["backend"]["type"], through the registry (which
    validates the block and raises BackendConfigError naming the field)."""
    return registry.build_backend(cfg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = load_settings(args.config)
    if not cfg:
        ap.error("no settings: set BROKER_CONFIG or pass --config")
    try:
        parse_extra_origins(cfg.get("approve_extra_origins"))
    except ValueError as e:
        raise SystemExit(f"config error: {e}") from None
    try:
        parse_trusted_proxies(cfg)
        parse_trusted_proxies(cfg, "approval_trusted_proxies")
        destguard.DestGuard.from_config(cfg)    # destination_deny_cidrs, own_ports: fail at startup, naming the field
    except ValueError as e:
        raise SystemExit(f"config error: {e}") from None
    risk.parse_auto_approve_max(cfg.get("risk"), "risk")    # fail at startup, naming the field
    risk.parse_auto_modes(cfg.get("risk"), "risk")          # fail at startup, naming the field
    grants.parse_config(cfg.get("timed_grants"))            # fail at startup, naming the field
    request_details.parse_config(cfg.get("request_details"))    # fail at startup, naming the field
    proposals.parse_config(cfg.get("guidance_proposals"))   # fail at startup, naming the field
    credreq.parse_config(cfg.get("credential_requests"))    # fail at startup, naming the field
    plans.parse_config(cfg.get("plans"))                    # fail at startup, naming the field
    sessions.parse_config(cfg.get("sessions"))              # fail at startup, naming the field
    clients.parse_config(cfg)           # legacy_client_key, enrollment, clients: fail at startup, naming the field
    try:
        backend = build_backend(cfg)
    except BackendConfigError as e:
        raise SystemExit(f"config error: {e}") from None
    notify.parse_action_policy(cfg.get("notify_actions"), "notify_actions")   # fail at startup
    if cfg.get("webpush") is not None:
        from .webpush import parse_actions
        parse_actions(cfg["webpush"])       # fail at startup on a bad webpush.actions
    presence.parse_config(cfg.get("notify_presence"))   # fail at startup, naming the field
    notify.parse_ha_hook(cfg.get("ha_hook"), _read)     # fail at startup, naming the field
    push = None
    if any(sp.get("type") == "webpush" for sp in cfg.get("notify") or []):
        from .webpush import store_from_config
        push = store_from_config(cfg)
    notifier = notify.build(cfg, _read, push_store=push)
    summarizer = None
    sc = cfg.get("summary")
    if sc:
        summarizer = riskmodel.build(sc, _read)     # validates, naming the field
        for w in getattr(summarizer, "config_warnings", ()):
            print("warning:", w, flush=True)
    broker = Broker(cfg, backend, notifier, audit=cfg.get("audit_log"), summarizer=summarizer,
                    background_load=True, push=push)
    bind = os.environ.get("BIND", "0.0.0.0")
    serve(broker,
          (bind, int(cfg.get("client_port") or 8800)),
          (bind, int(cfg.get("approval_port") or 8801)),
          _read(cfg["client_key_file"]))
    print("secret-broker listening", flush=True)
    def _stop(*a):
        try:
            broker.clients.flush()          # keep a revocation whose write failed earlier if the disk is back
        finally:
            os._exit(0)
    signal.signal(signal.SIGTERM, _stop)
    threading.Event().wait()


if __name__ == "__main__":
    main()

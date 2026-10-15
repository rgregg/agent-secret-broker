"""One-off: give secrets per-key variables (replaces a secret's `vars` map).

    python -m secret_broker.set_vars --config SETTINGS.json --spec vars.json          # dry run
    python -m secret_broker.set_vars --config SETTINGS.json --spec vars.json --apply

vars.json maps a secret name to its new variables, e.g.
    {"komodo": {"KOMODO_KEY": {"key": "key"}, "KOMODO_SECRET": {"key": "secret"}}}
Every `key` is checked against the stored value first; only key NAMES are
printed, never values. Run it with the broker stopped (it shares the vault
session state), like import_catalog.
"""
import argparse
import json
import sys
import time

from . import structured
from .__main__ import build_backend, load_settings
from .backends import BackendError


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--pause", type=float, default=3.0)
    args = ap.parse_args(argv)
    spec = json.load(open(args.spec))
    backend = build_backend(load_settings(args.config))
    rows = {}
    for r in backend.catalog():
        if r["meta"] and r["meta"].get("name"):
            rows[str(r["meta"]["name"]).lower()] = r
    failed = False
    for name, vars_ in sorted(spec.items()):
        row = rows.get(name.lower())
        if row is None:
            print(f"error  {name}: not in the catalog")
            failed = True
            continue
        item = row["item"]
        problem = None
        try:
            texts = {}
            for var, ref in vars_.items():
                field = ref.get("field") or "auto"
                if field not in texts:
                    texts[field] = backend.get(item, field)
                if ref.get("key"):
                    structured.get(texts[field], ref["key"])
        except (BackendError, structured.StructuredError) as e:
            problem = str(e)[:160]
        if problem:
            print(f"error  {name}: {problem}")
            failed = True
            continue
        print(f"{'apply' if args.apply else 'would'}  {name}: {sorted(vars_)}")
        if args.apply:
            meta = dict(row["meta"])
            meta["vars"] = vars_
            backend.set_meta(item, meta)
            time.sleep(args.pause)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

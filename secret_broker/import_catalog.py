"""One-off: move the `secrets` section of an old config file onto vault items.

    python -m secret_broker.import_catalog --config /data/config.json          # dry run
    python -m secret_broker.import_catalog --config /data/config.json --apply

Each secret becomes the `broker` custom field of the item that holds its value
(its first variable's item). Two secrets that share an item cannot both be
imported: an item carries exactly one catalog entry. Existing metadata is not
overwritten unless --force is given.
"""
import argparse
import json
import sys
import time

from .__main__ import build_backend, load_settings
from .backends import BackendError


def plan(secrets):
    """Return ([(item, meta)], [problem strings])."""
    out, problems, used = [], [], {}
    for name, sc in sorted(secrets.items()):
        vars_ = sc.get("vars") or {}
        if not vars_:
            problems.append(f"{name}: no variables")
            continue
        carrier = next(iter(vars_.values()))["item"]
        if carrier in used:
            problems.append(f"{name}: shares item {carrier!r} with {used[carrier]!r}")
            continue
        used[carrier] = name
        foreign = [v for v, r in vars_.items() if r["item"] != carrier]
        if foreign:
            problems.append(f"{name}: variables {foreign} use other items; a secret can only use its own item")
            continue
        meta = {k: v for k, v in sc.items() if k not in ("vars", "sensitivity")}
        meta["name"] = name
        meta["vars"] = {}
        for var, ref in vars_.items():
            r = {k: v for k, v in ref.items() if k != "item" or v != carrier}
            if r.get("field") in (None, "", "auto"):
                r.pop("field", None)
            meta["vars"][var] = r
        out.append((carrier, meta))
    return out, problems


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--force", action="store_true", help="overwrite existing metadata")
    ap.add_argument("--pause", type=float, default=3.0, help="seconds between writes")
    args = ap.parse_args(argv)
    cfg = load_settings(args.config)
    entries, problems = plan(cfg.get("secrets") or {})
    backend = build_backend(cfg)
    have = {r["item"] for r in backend.catalog()}
    bad = bool(problems)
    for p in problems:
        print("PROBLEM", p)
    for item, meta in entries:
        if item in have and not args.force:
            print(f"skip   {meta['name']:<32} item {item!r} already has metadata")
            continue
        print(f"{'write ' if args.apply else 'would '} {meta['name']:<32} -> {item!r}")
        if args.apply:
            # gentle on the server: it rate-limits bursts of syncs and logins
            for attempt in range(1, 5):
                try:
                    backend.set_meta(item, meta)
                    time.sleep(args.pause)
                    break
                except BackendError as e:
                    if "rate limit" in str(e).lower() or "too many" in str(e).lower():
                        print(f"  rate limited, waiting {30 * attempt}s")
                        time.sleep(30 * attempt)
                        continue
                    print(f"  FAILED: {e}")
                    bad = True
                    break
            else:
                print("  FAILED: still rate limited")
                bad = True
    if hasattr(backend, "close"):
        backend.close()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

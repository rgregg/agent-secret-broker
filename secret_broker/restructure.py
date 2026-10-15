"""One-off: turn migrated whole-file notes into properly shaped vault items.

    python -m secret_broker.restructure --config SETTINGS.json --spec plan.json          # dry run
    python -m secret_broker.restructure --config SETTINGS.json --spec plan.json --apply

plan.json is a list of entries, one per existing secret:

  {"secret": "unaspro-smb", "kind": "login",
   "username": "username", "password": "password", "uri": null,
   "notes": ["host", "notes"],
   "vars": {"UNASPRO_SMB_USERNAME": {"field": "username"},
            "UNASPRO_SMB_PASSWORD": {"field": "password"}}}

      -> a Login item with real username / password / URL fields; it replaces
         the old note item once every value reads back identical

  {"secret": "boat-api-keys", "kind": "split",
   "into": [{"name": "boat-happy-orca", "key": "happy-orca", "var": "HAPPY_ORCA_API_KEY"}]}

      -> one Login (password field) per value, each its own secret; the old
         item is deleted once every new one reads back identical

An old item is deleted only after verification, and never if anything differs.

Only key NAMES are printed. Run with the broker stopped, like import_catalog.
"""
import argparse
import json
import sys
import time

from . import structured
from .__main__ import build_backend, load_settings
from .backends import BackendError


def _carry(meta):
    return {k: v for k, v in meta.items() if k not in ("name", "vars", "_item", "_meta")}


def run(backend, entries, apply=False, pause=3.0, out=print):
    rows = {}
    for r in backend.catalog():
        if r["meta"] and r["meta"].get("name"):
            rows[str(r["meta"]["name"]).lower()] = r
    failed = False
    for e in entries:
        name = e["secret"]
        row = rows.get(name.lower())
        if row is None:
            out(f"error  {name}: not in the catalog")
            failed = True
            continue
        item, meta = row["item"], row["meta"]
        try:
            values = structured.parse(backend.get(item, "notes"))
            need = ([e["username"], e["password"]] + ([e["uri"]] if e.get("uri") else [])
                    + list(e.get("notes") or [])) if e["kind"] == "login" \
                else [p["key"] for p in e["into"]]
            missing = [k for k in need if k not in values]
            if missing:
                raise BackendError(f"keys not found: {missing}")
        except (BackendError, structured.StructuredError) as ex:
            out(f"error  {name}: {str(ex)[:160]}")
            failed = True
            continue
        verb = "apply" if apply else "would"
        if e["kind"] == "login":
            out(f"{verb}  {name}: Login(username<-{e['username']}, password<-{e['password']}"
                f"{', uri<-' + e['uri'] if e.get('uri') else ''}), "
                f"notes<-{e.get('notes') or []}, vars {sorted(e['vars'])}")
            if apply:
                tmp = f"{item} (login)"
                notes = "\n".join(f"{k}: {values[k]}" for k in e.get("notes") or []) or None
                backend.create_login(tmp, values[e["username"]], values[e["password"]],
                                     uri=values.get(e.get("uri")) if e.get("uri") else None,
                                     notes=notes)
                time.sleep(pause)
                if (backend.get(tmp, "username") != values[e["username"]]
                        or backend.get(tmp, "password") != values[e["password"]]):
                    out(f"error  {name}: new login does not match; old item kept")
                    failed = True
                    continue
                backend.delete(item)
                time.sleep(pause)
                backend.edit_item(tmp, new_name=item,
                                  meta={**_carry(meta), "name": name, "vars": e["vars"]})
                time.sleep(pause)
        else:
            out(f"{verb}  {name}: split into {[p['name'] for p in e['into']]}")
            if apply:
                ok = True
                for p in e["into"]:
                    backend.put(p["name"], "password", values[p["key"]], create=True,
                                meta={**_carry(meta), "name": p["name"],
                                      "vars": {p["var"]: {"field": "password"}}})
                    time.sleep(pause)
                    ok = ok and backend.get(p["name"], "password") == values[p["key"]]
                if not ok:
                    out(f"error  {name}: a new item does not match; old item kept")
                    failed = True
                    continue
                backend.delete(item)
                time.sleep(pause)
    return 1 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--pause", type=float, default=3.0)
    args = ap.parse_args(argv)
    backend = build_backend(load_settings(args.config))
    return run(backend, json.load(open(args.spec)), args.apply, args.pause)


if __name__ == "__main__":
    sys.exit(main())

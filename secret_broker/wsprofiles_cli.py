"""Admin CLI for WebSocket profiles: `python -m secret_broker ws-profile COMMAND` (stdlib only, no network).

Runs on the broker host (or anywhere the profile files are). It reads and writes only profile files and prints only
fixed messages and the profile's own fields; it never contacts the broker, the vault or a server.

    validate FILE...        check profile files (exit 0 all valid, 1 any invalid, 2 usage)
    new NAME [--from BUILTIN] [--dir DIR]   write a starter file; refuses to overwrite
    list [--dir DIR]        built-in and admin profiles, which one overrides which
    show NAME [--dir DIR]   the effective profile as JSON, then its risk notes

DIR defaults to `ws_profiles_dir` of the broker settings (--config FILE and/or BROKER_CONFIG, as for the broker),
else `ws-profiles/` next to its `audit_log`.
"""
import argparse
import json
import os
import sys

from . import wsprofiles as P

STARTER = {
    "name": None,
    "description": "Custom WebSocket profile: edit this line.",
    "handshake": {"steps": [{"send": {"type": "auth", "token": "{{VAR}}"}}, {"expect": {"type": "ok"}}]},
    "deny_send": [],
    "card_text": "Custom profile: edit this sentence to say what the client may do and what is blocked.",
    "risk_notes": ["Describe what a client signed in with this profile can do."],
}


class CliError(Exception):
    """A usage or safety problem; the message is safe to print."""


def _err(msg):
    print(f"error: {msg}", file=sys.stderr)


def _dir(args, load_settings):
    if args.dir:
        return args.dir
    cfg = {}
    try:
        cfg = load_settings(getattr(args, "config", None)) or {}
    except (OSError, ValueError):
        raise CliError("the broker settings could not be read (--config FILE / BROKER_CONFIG)") from None
    try:
        return P.parse_dir_config(cfg)
    except ValueError as e:
        raise CliError(str(e)) from None


def cmd_validate(args, load_settings):
    bad = 0
    for path in args.files:
        stem = os.path.basename(path)
        stem = stem[:-5] if stem.endswith(".json") else None
        try:
            prof = P.read_profile_file(path, expect_name=stem)
        except P.BadFile as e:
            bad += 1
            print(f"INVALID {path}: {e.detail}")
            continue
        extras = []
        if stem is None:
            extras.append("file name is not NAME.json: the broker would not load it")
        print(f"ok {path}: {prof['name']}" + (f" ({'; '.join(extras)})" if extras else ""))
        bad += bool(extras)
    return 1 if bad else 0


def _json_text(p):
    return json.dumps({k: v for k, v in p.items() if k not in ("source", "sha256") and v not in (None, {}, [])}, indent=2)


def cmd_new(args, load_settings):
    name = args.name
    if not isinstance(name, str) or len(name) > P.MAX_NAME or not P.NAME_RE.match(name):
        raise CliError("NAME must be kebab-case: lowercase letters, digits and single hyphens (up to 64)")
    directory = _dir(args, load_settings)
    if not directory:
        raise CliError("no profiles directory: pass --dir DIR or set ws_profiles_dir (or audit_log) in the broker settings")
    if args.source:
        bp, be = P.builtin()
        if args.source not in bp:
            raise CliError("--from must name a built-in profile (see `ws-profile list`)")
        body = {**bp[args.source], "name": name}
        body = {k: v for k, v in body.items() if v not in (None, {}, [])} | {"name": name}
        for k in ("deny_send", "allow_send", "rules"):
            if k in bp[args.source] and bp[args.source][k]:
                body[k] = bp[args.source][k]
        body["description"] = f"Copy of {args.source}: edit this line."[:P.MAX_TEXT]
    else:
        body = {**STARTER, "name": name}
    try:
        P.parse_profile(body, name)
    except ValueError:
        raise CliError("internal error: the starter profile does not validate") from None
    os.makedirs(directory, mode=0o755, exist_ok=True)
    target = os.path.join(directory, name + ".json")
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError:
        raise CliError(f"{target} already exists; not overwriting") from None
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(body, indent=2) + "\n")
    print(f"wrote {target}")
    bp, _ = P.builtin()
    if name in bp:
        print(f"note: this replaces the built-in profile {name!r} for every credential that uses it")
    print("edit it, then check it with: python -m secret_broker ws-profile validate " + target)
    return 0


def cmd_list(args, load_settings):
    directory = _dir(args, load_settings)
    reg = P.build_registry(directory)
    where = directory or "none (built-ins only)"
    print(f"admin profiles directory: {where}")
    if reg.dir_error is not None:
        print(f"ERROR: {reg.dir_error.detail}; every profile is treated as invalid")
    rows = []
    for n in reg.names():
        st, src = reg.status(n)
        if st == "ok":
            p = (reg.admin if src == "admin" else reg.builtin)[n]
            note = "overrides built-in" if src == "admin" and n in reg.builtin else ""
            rows.append((n, src, "ok", note, p["description"]))
        else:
            err = reg.admin_errors.get(n) or reg.builtin_errors.get(n) or reg.dir_error
            rows.append((n, src or "-", "INVALID", err.detail if err else "", ""))
            if src == "admin" and n in reg.builtin:
                rows[-1] = rows[-1][:3] + ("shadows built-in: " + rows[-1][3], "")
    for n, src, st, note, desc in rows:
        print(f"{n:32} {src:9} {st:8} {note}" + (f"  {desc}" if desc else ""))
    return 1 if any(r[2] == "INVALID" for r in rows) else 0


def cmd_show(args, load_settings):
    directory = _dir(args, load_settings)
    reg = P.build_registry(directory)
    try:
        p = reg.resolve(args.name)
    except ValueError as e:
        _err(str(e))
        return 1
    print(f"# {p['name']} ({p['source']})")
    print(_json_text(p))
    print("\nBlocks: " + f"{len(p['deny_send'])} message type(s), {len(p['rules'])} rule(s); "
          + ("allow-list of %d" % len(p["allow_send"]) if p["allow_send"] else "no allow-list"))
    print("Risk notes:" + ("" if p["risk_notes"] else " none"))
    for n in p["risk_notes"]:
        print(f"  - {n}")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="python -m secret_broker ws-profile",
                                 description="Manage WebSocket profiles (JSON files). No network.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--dir", default=None, help="profiles directory (default: ws_profiles_dir from the broker settings)")
        p.add_argument("--config", default=None, help="broker settings file (BROKER_CONFIG is read too)")
    p = sub.add_parser("validate", help="check profile files")
    p.add_argument("files", nargs="+", metavar="FILE")
    p.set_defaults(fn=cmd_validate)
    p = sub.add_parser("new", help="write a starter profile file (never overwrites)")
    p.add_argument("name", metavar="NAME")
    p.add_argument("--from", dest="source", default=None, metavar="BUILTIN", help="start from a built-in profile")
    common(p)
    p.set_defaults(fn=cmd_new)
    p = sub.add_parser("list", help="built-in and admin profiles")
    common(p)
    p.set_defaults(fn=cmd_list)
    p = sub.add_parser("show", help="the effective profile and its risk notes")
    p.add_argument("name", metavar="NAME")
    common(p)
    p.set_defaults(fn=cmd_show)
    return ap


def main(argv, load_settings):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args, load_settings)
    except CliError as e:
        _err(e)
    except OSError as e:
        _err(f"{type(e).__name__}: {e.strerror or 'failed'}")
    return 1

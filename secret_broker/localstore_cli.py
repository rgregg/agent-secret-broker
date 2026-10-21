"""Admin CLI for the encrypted local store: `python -m secret_broker.localstore COMMAND`.

Runs on the broker host (or any machine that can read the store and its key). Every
command prints only item NAMES, shapes and counts; a value is never printed, never
taken from argv (values come from stdin or a hidden prompt) and never put in an
error message. The store file is created 0600 and the CLI refuses to open one that
other users can read.

    init           create a store (and a recovery key, printed once)
    list           names and shapes
    show NAME      metadata and field names, never values
    add NAME       add a login or note (values from stdin / hidden prompt)
    set-meta NAME FILE      replace an item's broker metadata from a JSON file ("-" = stdin)
    delete NAME
    change-key     re-wrap the data key under a new passphrase / key
    rotate-dek     new data key, re-encrypt everything
    import-bw      one-time copy of the broker's Bitwarden/Vaultwarden collection
    import-env FILE   one-time import of KEY=value lines (then delete the file)
    export-names   names only, one per line
"""
import argparse
import base64
import contextlib
import getpass
import json
import os
import re
import sys

from .backends import registry
from .backends.base import LOGIN, NOTE, BackendConfigError, BackendError, Item, auto_shape
from .backends.local import LocalBackend
from .backends.localstore import (EnvKeySource, FileKeySource, Key, LocalStore, StoreError,
                                  create_store, key_source_from_config)


class CliError(Exception):
    """A usage or safety problem; the message is safe to print."""


# -- plumbing -----------------------------------------------------------------------
def _err(msg):
    print(f"error: {msg}", file=sys.stderr)


def _check_store_mode(path):
    try:
        mode = os.stat(path).st_mode & 0o777
    except FileNotFoundError:
        raise CliError(f"store {path} does not exist (run init)") from None
    if mode & 0o077:
        raise CliError(f"store {path} is accessible by other users (mode {mode:o}); "
                       f"run: chmod 600 {path}")


def _warn_key_file(path):
    with contextlib.suppress(OSError):
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            print(f"warning: key file {path} is readable by other users (mode {mode:o})",
                  file=sys.stderr)


def _key_source(args, prefix=""):
    """(path, key source) from --config, or from --store plus --key-file / --key-env."""
    cfg_path = getattr(args, "config", None)
    kf, ke = getattr(args, prefix + "key_file", None), getattr(args, prefix + "key_env", None)
    if cfg_path and not prefix:
        with open(cfg_path) as f:
            b = json.load(f).get("backend") or {}
        if b.get("type") != "local":
            raise CliError(f"{cfg_path}: backend.type is not 'local'")
        try:
            return b["path"], key_source_from_config(b.get("key_source"))
        except (KeyError, BackendConfigError) as e:
            raise CliError(f"{cfg_path}: {e}") from None
    if kf and ke:
        raise CliError("give one of --key-file / --key-env, not both")
    if kf:
        _warn_key_file(kf)
        return getattr(args, "store", None), FileKeySource(kf)
    if ke:
        return getattr(args, "store", None), EnvKeySource(ke)
    raise CliError("a key source is required: --key-file PATH or --key-env NAME (or --config FILE)")


def _open(args, need_mode=True):
    path, ks = _key_source(args)
    path = getattr(args, "store", None) or path
    if not path:
        raise CliError("--store PATH is required (or --config FILE)")
    if need_mode:
        _check_store_mode(path)
    return path, ks


def _backend(args):
    path, ks = _open(args)
    return LocalBackend(path, ks, idle_timeout=0)


def _new_key(args):
    """A Key from --new-key-file / --new-key-env, or a hidden prompt (twice)."""
    if args.new_key_file and args.new_key_env:
        raise CliError("give one of --new-key-file / --new-key-env, not both")
    if args.new_key_file:
        return FileKeySource(args.new_key_file).read()
    if args.new_key_env:
        return EnvKeySource(args.new_key_env).read()
    if not sys.stdin.isatty():
        raise CliError("give the new key with --new-key-file / --new-key-env (no terminal to prompt on)")
    a = getpass.getpass("new passphrase: ")
    if not a or a != getpass.getpass("again: "):
        raise CliError("passphrases are empty or do not match")
    return Key(a)


def _generated_key():
    return base64.b64encode(os.urandom(32)).decode("ascii")


def _write_new_key_file(path):
    """Create `path` (0600, never overwriting) holding a fresh random raw key."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(_generated_key() + "\n")


def _read_secret_text(prompt):
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.read()


def _strip_one_newline(text):
    return text[:-1] if text.endswith("\n") else text


def _shape(it):
    d = it.to_dict()
    parts = [it.kind]
    if it.kind == LOGIN:
        parts += [k for k in ("username", "password") if d.get(k)]
    if it.kind == "ssh_key":
        parts.append("key pair")
    if it.notes:
        parts.append("notes")
    parts += [f"field:{k}" for k in sorted(it.fields)]
    if it.uris:
        parts.append(f"{len(it.uris)} uri")
    parts.append("broker" if it.meta is not None else "no-meta")
    return " ".join(parts)


# -- commands -------------------------------------------------------------------------
def cmd_init(args):
    path, ks = _key_source(args)
    path = args.store or path
    if not path:
        raise CliError("--store PATH is required (or --config FILE)")
    kf = args.key_file
    if kf and not os.path.exists(kf):
        if not args.generate_key:
            raise CliError(f"key file {kf} does not exist (use --generate-key to create one)")
        _write_new_key_file(kf)
        print(f"created key file {kf} (mode 600); keep it apart from the store")
    elif args.generate_key:
        raise CliError("--generate-key needs --key-file naming a file that does not exist yet")
    key = ks.read()
    if os.path.exists(path):
        if not args.force:
            raise CliError(f"{path} already exists; use --force to replace it "
                           "(the old file is kept as .replaced)")
        os.replace(path, path + ".replaced")
        print(f"previous store kept as {path}.replaced")
    recovery = None
    recovery_text = None
    if not args.no_recovery:
        recovery_text = _generated_key()
        recovery = Key(recovery_text)
    create_store(path, key, recovery_key=recovery)
    os.chmod(path, 0o600)
    print(f"created {path} (mode 600)")
    if recovery_text:
        print("RECOVERY KEY (shown once; store it offline, it opens the store without your key):")
        print(recovery_text)
    else:
        print("no recovery key: if the key is lost the store cannot be opened")
    return 0


def cmd_list(args):
    b = _backend(args)
    try:
        items = sorted(b.export_items(), key=lambda i: i.name.lower())
    finally:
        b.close()
    for it in items:
        print(f"{it.name}\t{_shape(it)}")
    print(f"{len(items)} items", file=sys.stderr)
    return 0


def cmd_show(args):
    b = _backend(args)
    try:
        wanted = args.name
        items = {i.name: i for i in b.export_items()}
    finally:
        b.close()
    it = items.get(wanted) or next((i for n, i in items.items() if n.lower() == wanted.lower()), None)
    if it is None:
        raise CliError(f"item {wanted!r} not found")
    print(f"name:   {it.name}")
    print(f"kind:   {it.kind}")
    print(f"shape:  {_shape(it)}")
    print("fields: " + (", ".join(sorted(it.fields)) or "(none)"))
    print(f"adopts: {'yes' if auto_shape(it) else 'no (nothing usable)'}"
          + ("" if it.meta is None else " (has metadata; adoption not used)"))
    if it.meta is not None:
        print("broker metadata:")
        print(json.dumps(it.meta, indent=2, sort_keys=True))
    return 0


def _read_meta_file(path):
    try:
        text = sys.stdin.read() if path == "-" else open(path).read()
        meta = json.loads(text)
    except (OSError, ValueError) as e:
        raise CliError(f"cannot read metadata from {path}: {type(e).__name__}") from None
    if not isinstance(meta, dict):
        raise CliError("metadata must be a JSON object")
    return meta


def cmd_add(args):
    if args.meta == "-":
        raise CliError("--meta - would clash with values on stdin; use a file")
    tty = sys.stdin.isatty()
    meta = _read_meta_file(args.meta) if args.meta else None
    if args.json:
        item = _item_from_json(args.name, sys.stdin.read(), meta, args.kind)
    elif args.kind == LOGIN:
        if not tty:
            raise CliError("a login needs a terminal to prompt on, or --json with a JSON object on stdin")
        user = input("username: ")
        item = Item(args.name, LOGIN, username=user or None, password=getpass.getpass("password: "),
                    meta=meta)
    elif args.field:
        if not tty:
            raise CliError("custom fields are prompted for on a terminal; use --json instead")
        item = Item(args.name, NOTE, meta=meta,
                    fields={f: getpass.getpass(f"value for {f}: ") for f in args.field})
    else:
        item = Item(args.name, NOTE, notes=_strip_one_newline(_read_secret_text("note text: ")),
                    meta=meta)
    if args.uri and not item.uris:
        item.uris = [args.uri]
    b = _backend(args)
    try:
        b.import_items([item], overwrite=False)
    finally:
        b.close()
    print(f"added {args.name} ({item.kind})")
    return 0


def _item_from_json(name, text, meta, kind=None):
    try:
        d = json.loads(text)
    except ValueError:
        raise CliError("stdin is not valid JSON") from None
    if not isinstance(d, dict):
        raise CliError("stdin JSON must be an object")
    allowed = {"username", "password", "notes", "uris", "fields", "kind"}
    extra = sorted(set(d) - allowed)
    if extra:
        raise CliError(f"unknown keys in stdin JSON: {extra}")
    k = kind or d.get("kind") or (LOGIN if d.get("password") or d.get("username") else NOTE)
    if k not in (LOGIN, NOTE):
        raise CliError("kind must be login or note")
    return Item(name, k, username=d.get("username"), password=d.get("password"),
                notes=d.get("notes"), uris=d.get("uris") or [], fields=d.get("fields") or {},
                meta=meta)


def cmd_set_meta(args):
    meta = _read_meta_file(args.file)
    b = _backend(args)
    try:
        b.set_meta(args.name, meta)
    finally:
        b.close()
    print(f"metadata of {args.name} replaced")
    return 0


def cmd_delete(args):
    b = _backend(args)
    try:
        if not args.yes:
            if not sys.stdin.isatty():
                raise CliError("refusing to delete without --yes (no terminal to confirm on)")
            if input(f"delete {args.name}? type the name to confirm: ") != args.name:
                raise CliError("not confirmed; nothing deleted")
        have = {i["item"] for i in b.catalog()} | {i.name for i in b.export_items()}
        if args.name not in have and args.name.lower() not in {h.lower() for h in have}:
            raise CliError(f"item {args.name!r} not found")
        b.delete(args.name)
    finally:
        b.close()
    print(f"deleted {args.name}")
    return 0


def cmd_export_names(args):
    b = _backend(args)
    try:
        for it in sorted(b.export_items(), key=lambda i: i.name.lower()):
            print(it.name)
    finally:
        b.close()
    return 0


def _bak_notice(path, removed):
    """The previous generation (.bak) still opens with the key that was just replaced, so the
    store removes it; copies made elsewhere are the operator's to deal with."""
    if removed:
        print(f"removed {path}.bak: it was the previous file and still opened with the old key")
    print("note: backups or snapshots of the store made earlier still open with the old key")


def cmd_change_key(args):
    path, ks = _open(args)
    store = LocalStore(path, ks, idle_timeout=0)
    try:
        new = _new_key(args)
        if args.wrap not in store.wrap_ids():
            raise CliError(f"the store has no wrap {args.wrap!r} (it has {store.wrap_ids()})")
        store.rewrap(args.wrap, new)
        removed = getattr(store, "bak_removed", False)
    finally:
        store.close()
    print(f"wrap {args.wrap!r} now opens with the new key; update the broker's key source, "
          "then restart or wait for its next unlock")
    _bak_notice(path, removed)
    return 0


def cmd_rotate_dek(args):
    path, ks = _open(args)
    store = LocalStore(path, ks, idle_timeout=0)
    try:
        others = [w for w in store.wrap_ids() if w != "primary"]
        keys = {"primary": ks.read()}
        new_recovery = None
        if args.new_recovery:
            new_recovery = _generated_key()
            keys["recovery"] = Key(new_recovery)
        elif args.recovery_key_file or args.recovery_key_env:
            keys["recovery"] = (FileKeySource(args.recovery_key_file) if args.recovery_key_file
                                else EnvKeySource(args.recovery_key_env)).read()
        elif others and not args.drop_other_wraps:
            raise CliError(f"the store has other key wraps {others}; rotating the data key "
                           "needs their keys: give --recovery-key-file/--recovery-key-env, "
                           "--new-recovery, or --drop-other-wraps")
        store.rotate_dek(keys)
        removed = getattr(store, "bak_removed", False)
    finally:
        store.close()
    print("data key rotated; all contents re-encrypted")
    _bak_notice(path, removed)
    if new_recovery:
        print("NEW RECOVERY KEY (shown once; the old one no longer works):")
        print(new_recovery)
    return 0


def build_source_backend(path):
    """The Bitwarden/Vaultwarden backend described by a broker config file. A seam
    for tests."""
    with open(path) as f:
        cfg = json.load(f)
    b = cfg.get("backend") or {}
    if b.get("type") != "bw":
        raise CliError(f"{path}: backend.type must be 'bw' to import from it")
    return registry.build_backend(cfg)


def _same(a, b):
    return a.to_dict() == b.to_dict()


def cmd_import_bw(args):
    path, ks = _open(args)
    src = build_source_backend(args.bw_config)
    try:
        if "export_items" not in src.capabilities:
            raise CliError("the source backend cannot export items")
        items = src.export_items()
    finally:
        src.close()
    dest = LocalBackend(path, ks, idle_timeout=0)
    try:
        have = {i.name.lower() for i in dest.export_items()}
        clash = sorted(i.name for i in items if i.name.lower() in have)
        if clash and not (args.skip_existing or args.overwrite):
            raise CliError(f"{len(clash)} item(s) already exist in the store: {clash[:10]}; "
                           "use --skip-existing or --overwrite")
        todo = [i for i in items if not (i.name.lower() in have and args.skip_existing)]
        names = sorted(i.name for i in todo)
        if args.dry_run:
            for n in names:
                print(f"would import {n}")
            print(f"{len(names)} items would be imported ({len(items) - len(todo)} skipped)")
            return 0
        written = dest.import_items(todo, overwrite=args.overwrite)
        got = {i.name: i for i in dest.export_items()}
        bad = [i.name for i in todo if i.name not in got or not _same(i, got[i.name])]
        if bad:
            raise CliError(f"read-back check FAILED for {sorted(bad)}; the source is untouched")
    finally:
        dest.close()
    for n in sorted(written):
        print(f"imported {n}")
    print(f"{len(written)} items imported and verified by read-back "
          f"({len(items) - len(todo)} skipped); nothing was changed in the source")
    return 0


_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def parse_env_text(text):
    """[(KEY, value)] from `KEY=value` lines. Blank lines and # comments are skipped;
    a matching pair of single or double quotes around the value is removed."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _ENV_LINE.match(line)
        if not m:
            raise CliError(f"line {n} is not KEY=value")
        key, val = m.groups()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        out.append((key, val))
    return out


def cmd_import_env(args):
    try:
        with open(args.file) as f:
            pairs = parse_env_text(f.read())
    except OSError as e:
        raise CliError(f"cannot read {args.file}: {e.strerror}") from None
    if not pairs:
        raise CliError("no KEY=value lines found")
    dup = sorted({k for k, _ in pairs if sum(1 for q, _ in pairs if q == k) > 1})
    if dup:
        raise CliError(f"keys defined more than once: {dup}")
    b = _backend(args)
    try:
        have = {i.name.lower() for i in b.export_items()}
        items, skipped = [], []
        for key, val in pairs:
            if key.lower() in have and not args.overwrite:
                skipped.append(key)
                continue
            items.append(Item(key, NOTE, notes=val, meta={
                "name": key.lower().replace("_", "-"), "approval": "prompt",
                "vars": {key: {"field": "notes"}}}))
        if items:
            b.import_items(items, overwrite=args.overwrite)
    finally:
        b.close()
    for it in items:
        print(f"imported {it.name}")
    for k in skipped:
        print(f"skipped {k} (already in the store; --overwrite replaces it)")
    print(f"{len(items)} items imported, {len(skipped)} skipped")
    print(f"now delete {args.file}: it holds the same values in plaintext")
    return 0


# -- argument parsing ----------------------------------------------------------------------
def _common(p):
    p.add_argument("--store", help="path of the encrypted store file")
    p.add_argument("--config", help="a broker config file whose backend block is type 'local'")
    p.add_argument("--key-file", help="file holding the passphrase or a base64 32-byte key")
    p.add_argument("--key-env", help="environment variable holding the same")


def build_parser():
    ap = argparse.ArgumentParser(prog="python -m secret_broker.localstore",
                                 description="Admin tool for the encrypted local store. "
                                             "Prints names and counts only, never values.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a new store")
    _common(p)
    p.add_argument("--no-recovery", action="store_true", help="do not create a recovery key")
    p.add_argument("--generate-key", action="store_true",
                   help="create --key-file with a fresh random key (the file must not exist)")
    p.add_argument("--force", action="store_true", help="replace an existing store (kept as .replaced)")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("list", help="names and shapes")
    _common(p)
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("show", help="metadata and field names of one item")
    _common(p)
    p.add_argument("name")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("add", help="add a login or note (values from stdin or a hidden prompt)")
    _common(p)
    p.add_argument("name")
    p.add_argument("--kind", choices=[LOGIN, NOTE], default=None,
                   help="login or note (default: note, or inferred from --json)")
    p.add_argument("--field", action="append", help="name of a custom field to prompt for (note kind)")
    p.add_argument("--uri", help="a login's URL (not secret)")
    p.add_argument("--meta", help="JSON file with the broker metadata object")
    p.add_argument("--json", action="store_true",
                   help="read a JSON object (username, password, notes, uris, fields) from stdin")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("set-meta", help="replace an item's broker metadata from a JSON file")
    _common(p)
    p.add_argument("name")
    p.add_argument("file", help="JSON file, or - for stdin")
    p.set_defaults(fn=cmd_set_meta)

    p = sub.add_parser("delete", help="delete an item")
    _common(p)
    p.add_argument("name")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(fn=cmd_delete)

    p = sub.add_parser("change-key", help="re-wrap the data key under a new passphrase or key")
    _common(p)
    p.add_argument("--wrap", default="primary", help="which wrap to replace (primary or recovery)")
    p.add_argument("--new-key-file")
    p.add_argument("--new-key-env")
    p.set_defaults(fn=cmd_change_key)

    p = sub.add_parser("rotate-dek", help="new data key; re-encrypts the contents")
    _common(p)
    p.add_argument("--new-recovery", action="store_true", help="also make a new recovery key")
    p.add_argument("--recovery-key-file")
    p.add_argument("--recovery-key-env")
    p.add_argument("--drop-other-wraps", action="store_true",
                   help="discard wraps whose keys are not supplied (the recovery key stops working)")
    p.set_defaults(fn=cmd_rotate_dek)

    p = sub.add_parser("import-bw", help="copy the broker's Bitwarden collection into the store")
    _common(p)
    p.add_argument("--bw-config", required=True,
                   help="a broker config file with a backend block of type 'bw'")
    p.add_argument("--skip-existing", action="store_true")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_import_bw)

    p = sub.add_parser("import-env", help="import KEY=value lines as env-mode items")
    _common(p)
    p.add_argument("file")
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(fn=cmd_import_env)

    p = sub.add_parser("export-names", help="names only")
    _common(p)
    p.set_defaults(fn=cmd_export_names)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except CliError as e:
        _err(e)
    except StoreError as e:
        _err(f"{e} [{e.reason}]")
    except (BackendError, BackendConfigError) as e:
        _err(e)
    except OSError as e:
        _err(f"{type(e).__name__}: {e.strerror or 'failed'}")
    except json.JSONDecodeError:
        _err("a JSON file could not be parsed")
    return 1


if __name__ == "__main__":
    sys.exit(main())

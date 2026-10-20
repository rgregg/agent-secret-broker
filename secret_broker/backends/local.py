"""LocalBackend: secrets in one local AES-256-GCM encrypted file (localstore.py).

No vault server needed. Items have the same shape and behavior as vault items,
including `broker` metadata and adoption of items without it. See
docs/reference.md ("Local encrypted backend")."""
import copy

from .base import (AUTO_ALIASES, CAP_ADOPTS, CAP_CREATE_LOGIN, CAP_EDIT_ITEM, CAP_EXPORT_ITEMS,
                   CAP_IMPORT_ITEMS, CAP_ON_EVENT, CAP_SET_META, CAP_WARM, LOGIN, META_FIELD, NOTE,
                   PREVIOUS_FIELDS, RESERVED_FIELDS, SSH_KEY, BackendConfigError, BackendConflict,
                   BackendInvalid, BackendNotFound, BackendSpec, Item, VaultBackend, auto_field_for,
                   auto_shape, check_item_args, clean_meta, lookup_name, now_iso)
from .localstore import LocalStore, key_source_from_config


def _kind(it):
    return it.get("type") if it.get("type") in (LOGIN, NOTE, SSH_KEY) else NOTE


class LocalBackend(VaultBackend):
    """The contract on top of a `LocalStore`. A wrong or missing key, or a damaged
    file, raises `StoreError` (a `BackendUnavailable`) from every call that needs
    the contents; nothing is read partially and nothing is overwritten."""
    kind = "local"
    capabilities = frozenset({CAP_SET_META, CAP_CREATE_LOGIN, CAP_EDIT_ITEM, CAP_WARM, CAP_ON_EVENT,
                              CAP_ADOPTS, CAP_EXPORT_ITEMS, CAP_IMPORT_ITEMS})

    def __init__(self, path, key_source, idle_timeout=300):
        self._store = LocalStore(path, key_source, idle_timeout)

    @property
    def on_event(self):
        return self._store.on_event

    @on_event.setter
    def on_event(self, fn):
        self._store.on_event = fn

    @classmethod
    def from_config(cls, b):
        validate(b)
        return cls(b["path"], key_source_from_config(b.get("key_source")), b.get("idle_timeout", 300))

    # -- lookup ------------------------------------------------------------
    @staticmethod
    def _find(items, name):
        """Exact name, else a unique case-insensitive match; None if absent."""
        return lookup_name(items, name)

    def _require(self, items, name):
        key = self._find(items, name)
        if key is None:
            raise BackendNotFound(f"item {name!r} not found")
        return key

    # -- reads -------------------------------------------------------------
    def get(self, item, field):
        check_item_args(item)
        if field == META_FIELD:
            raise BackendInvalid("the broker metadata field is not a secret")

        def pick(items):
            it = items[self._require(items, item)]
            kind = _kind(it)
            f = auto_field_for(kind) if field in AUTO_ALIASES else field
            if f in ("password", "username") and kind == LOGIN:
                return it.get(f) or ""
            if f == "private_key" and kind == SSH_KEY:
                return it.get("private_key") or ""
            if f == "notes":
                return (it.get("notes") or "").strip()
            if f in PREVIOUS_FIELDS and it.get(f):
                return it[f]
            if f in (it.get("fields") or {}) and f not in RESERVED_FIELDS:
                return it["fields"][f] or ""
            raise BackendNotFound(f"field {f!r} not found on item {item!r}")
        return self._store.read(pick)

    def catalog(self):
        def rows(items):
            out = []
            for name, it in items.items():
                meta = it.get(META_FIELD)
                if meta:
                    out.append({"item": name,
                                "meta": copy.deepcopy(meta) if isinstance(meta, dict) else None})
                else:
                    shape = auto_shape(Item.from_dict(name, it))
                    if shape:
                        out.append({"item": name, "meta": None, "auto": shape})
            return out
        return self._store.read(rows)

    def warm(self):
        self._store.warm()

    def close(self):
        self._store.close()

    def export_items(self):
        return self._store.read(lambda items: [Item.from_dict(n, copy.deepcopy(it))
                                               for n, it in items.items()])

    # -- writes ------------------------------------------------------------
    def put(self, item, field, value, create=False, keep_previous=False, meta=None):
        check_item_args(item, value)
        if field in RESERVED_FIELDS:
            raise BackendInvalid(f"field {field!r} is reserved")
        meta = clean_meta(meta) if meta is not None else None

        def apply(items):
            existing = self._find(items, item)
            if create:
                if existing is not None:
                    raise BackendConflict(f"item {item!r} already exists")
                f = "notes" if field in AUTO_ALIASES else field
                base = {"notes": None, "uris": [], "fields": {}}
                if f == "password":
                    new = {"type": LOGIN, "username": None, "password": value, **base}
                elif f == "notes":
                    new = {"type": NOTE, **base, "notes": value}
                elif f == "private_key":
                    pub = (meta or {}).get("ssh_public_key")
                    if not isinstance(pub, str) or not pub:
                        raise BackendInvalid("an SSH key item needs its public key")
                    new = {"type": SSH_KEY, **base, "private_key": value, "public_key": pub}
                else:
                    new = {"type": NOTE, **base, "fields": {f: value}}
                if meta is not None:
                    new[META_FIELD] = meta
                items[item] = new
                return
            if existing is None:
                raise BackendNotFound(f"item {item!r} not found")
            it = items[existing]
            kind = _kind(it)
            f = auto_field_for(kind) if field in AUTO_ALIASES else field
            if f == "password" and kind == LOGIN:
                old, it["password"] = it.get("password"), value
            elif f == "private_key" and kind == SSH_KEY:
                old, it["private_key"] = it.get("private_key"), value
            elif f == "notes":
                old, it["notes"] = it.get("notes"), value
            elif f in (it.get("fields") or {}):
                old, it["fields"][f] = it["fields"][f], value
            else:
                raise BackendNotFound(f"field {f!r} not found on item {item!r}")
            if keep_previous and old:
                it["previous_value"] = old
                it["previous_replaced_at"] = now_iso()
            if meta is not None:
                it[META_FIELD] = meta
        self._store.mutate(apply)

    def set_meta(self, item, meta):
        check_item_args(item)
        meta = clean_meta(meta)

        def apply(items):
            items[self._require(items, item)][META_FIELD] = meta
        self._store.mutate(apply)

    def create_login(self, item, username, password, uri=None, notes=None, meta=None):
        check_item_args(item)
        meta = clean_meta(meta) if meta is not None else None

        def apply(items):
            if self._find(items, item) is not None:
                raise BackendConflict(f"item {item!r} already exists")
            new = {"type": LOGIN, "username": username, "password": password,
                   "notes": notes or None, "uris": [uri] if uri else [], "fields": {}}
            if meta is not None:
                new[META_FIELD] = meta
            items[item] = new
        self._store.mutate(apply)

    def edit_item(self, item, new_name=None, meta=None, drop_meta=False):
        check_item_args(item)
        meta = clean_meta(meta) if meta is not None else None

        def apply(items):
            key = self._require(items, item)
            it = items[key]
            if new_name:
                if self._find(items, new_name) is not None:
                    raise BackendConflict(f"item {new_name!r} already exists")
                renamed = {(new_name if k == key else k): v for k, v in items.items()}
                items.clear()
                items.update(renamed)
            if drop_meta:
                it.pop(META_FIELD, None)
            if meta is not None:
                it[META_FIELD] = meta
        self._store.mutate(apply)

    def delete(self, item):
        check_item_args(item)

        def apply(items):
            key = self._find(items, item)
            if key is not None:
                del items[key]
        self._store.mutate(apply)

    def import_items(self, items, overwrite=False):
        items = [i.validate() for i in items]

        def apply(doc):
            for i in items:
                have = self._find(doc, i.name)
                if have is not None and not overwrite:
                    raise BackendConflict(f"item {i.name!r} already exists")
                if have is not None:
                    del doc[have]
                doc[i.name] = i.to_dict()
        self._store.mutate(apply)
        return [i.name for i in items]


# -- configuration ---------------------------------------------------------------
_ALLOWED = {"type", "path", "key_source", "idle_timeout"}


def validate(b):
    for k in b:
        if k not in _ALLOWED:
            raise BackendConfigError(f"backend.{k}: unknown field for type 'local'")
    if not isinstance(b.get("path"), str) or not b["path"]:
        raise BackendConfigError("backend.path: required (path of the encrypted store file)")
    idle = b.get("idle_timeout", 300)
    if isinstance(idle, bool) or not isinstance(idle, (int, float)) or idle < 0:
        raise BackendConfigError("backend.idle_timeout: must be a number of seconds >= 0")
    key_source_from_config(b.get("key_source"))


SPEC = BackendSpec(
    name="local", build=LocalBackend.from_config, validate=validate,
    doc="One AES-256-GCM encrypted file. Keys: path, key_source "
        "({type: file, path} | {type: env, name}), idle_timeout.")

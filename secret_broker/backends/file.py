"""Legacy plaintext JSON backend: {item: {field: value}}. Tests and bootstrapping
only; it never writes the file back, so changes last as long as the process."""
import json
import threading

from .base import (AUTO_ALIASES, CAP_SET_META, META_FIELD, RESERVED_FIELDS, BackendConfigError,
                   BackendConflict, BackendInvalid, BackendNotFound, BackendSpec, VaultBackend,
                   catalog_rows, check_item_args, clean_meta, lookup_name, now_iso)


class FileBackend(VaultBackend):
    kind = "file"
    capabilities = frozenset({CAP_SET_META})
    _lock = threading.RLock()           # class-level: instances built with __new__ in tests work too

    def __init__(self, path):
        with open(path) as f:
            self._data = json.load(f)

    def _find(self, item):
        key = lookup_name(self._data, item)
        if key is None:
            raise BackendNotFound(f"item {item!r} not found")
        return key

    @staticmethod
    def _auto(rec):
        if "private_key" in rec and "notes" not in rec:
            return "private_key"
        return "password" if "password" in rec and "notes" not in rec else "notes"

    def get(self, item, field):
        check_item_args(item)
        if field == META_FIELD:
            raise BackendInvalid("the broker metadata field is not a secret")
        with self._lock:
            rec = self._data[self._find(item)]
            f = self._auto(rec) if field in AUTO_ALIASES else field
            if f not in rec:
                raise BackendNotFound(f"{item}/{f} not found")
            return rec[f]

    def put(self, item, field, value, create=False, keep_previous=False, meta=None):
        check_item_args(item, value)
        if field in RESERVED_FIELDS:
            raise BackendInvalid(f"field {field!r} is reserved")
        meta = clean_meta(meta) if meta is not None else None
        with self._lock:
            existing = lookup_name(self._data, item)
            if create:
                if existing is not None:
                    raise BackendConflict(f"item {item!r} already exists")
                rec = self._data[item] = {}
                f = "notes" if field in AUTO_ALIASES else field
                if f == "private_key" and not (meta or {}).get("ssh_public_key"):
                    del self._data[item]
                    raise BackendInvalid("an SSH key item needs its public key")
            else:
                if existing is None:
                    raise BackendNotFound(f"item {item!r} not found")
                rec = self._data[existing]
                f = self._auto(rec) if field in AUTO_ALIASES else field
                if f not in rec:
                    raise BackendNotFound(f"field {f!r} not found on item {item!r}")
            if keep_previous and rec.get(f):
                rec["previous_value"], rec["previous_replaced_at"] = rec[f], now_iso()
            rec[f] = value
            if meta is not None:
                rec[META_FIELD] = json.dumps(meta)

    def catalog(self):
        with self._lock:
            return catalog_rows((item, rec.get(META_FIELD)) for item, rec in self._data.items())

    def set_meta(self, item, meta):
        meta = clean_meta(meta)
        with self._lock:
            self._data[self._find(item)][META_FIELD] = json.dumps(meta)

    def delete(self, item):
        with self._lock:
            key = lookup_name(self._data, item)
            if key is not None:
                del self._data[key]


def _validate(b):
    if not isinstance(b.get("path"), str) or not b["path"]:
        raise BackendConfigError("backend.path: required (a JSON file; tests only)")


def _build(b):
    return FileBackend(b["path"])


SPEC = BackendSpec("file", _build, _validate,
                   "Plaintext JSON file {item: {field: value}}; tests and bootstrapping only. Key: path.")

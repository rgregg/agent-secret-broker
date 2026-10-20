"""MemoryBackend: the smallest correct `VaultBackend`. Items live in a dict, nothing
persists. For tests and embedding, and as the worked example for third-party
backends: it passes tests/backend_contract.py in about 150 lines."""
import threading

from .base import (AUTO_ALIASES, CAP_ADOPTS, CAP_CREATE_LOGIN, CAP_EDIT_ITEM, CAP_EXPORT_ITEMS,
                   CAP_IMPORT_ITEMS, CAP_SET_META, LOGIN, META_FIELD, NOTE, PREVIOUS_FIELDS,
                   RESERVED_FIELDS, SSH_KEY, BackendConflict, BackendInvalid, BackendNotFound,
                   Item, VaultBackend, BackendSpec, auto_shape, check_item_args, clean_meta,
                   lookup_name, now_iso)


class MemoryBackend(VaultBackend):
    kind = "memory"
    capabilities = frozenset({CAP_SET_META, CAP_ADOPTS, CAP_CREATE_LOGIN, CAP_EDIT_ITEM,
                              CAP_EXPORT_ITEMS, CAP_IMPORT_ITEMS})

    def __init__(self):
        self._items = {}                    # name -> Item
        self._prev = {}                     # name -> {"previous_value", "previous_replaced_at"}
        self._lock = threading.RLock()

    def _find(self, name):
        key = lookup_name(self._items, name)
        if key is None:
            raise BackendNotFound(f"item {name!r} not found")
        return key

    @staticmethod
    def _slot(it, field):
        """(attribute-or-dict, key) holding `field` on `it`, or None."""
        if field in ("password", "username") and it.kind == LOGIN:
            return it, field
        if field == "notes":
            return it, "notes"
        if field == "private_key" and it.kind == SSH_KEY:
            return it, "private_key"
        return (it.fields, field) if field in it.fields else None

    @staticmethod
    def _read(slot):
        obj, key = slot
        v = obj.get(key) if isinstance(obj, dict) else getattr(obj, key)
        return v or ""

    def get(self, item, field):
        check_item_args(item)
        if field == META_FIELD:
            raise BackendInvalid("the broker metadata field is not a secret")
        with self._lock:
            name = self._find(item)
            it = self._items[name]
            f = it.auto_field() if field in AUTO_ALIASES else field
            if f in PREVIOUS_FIELDS and self._prev.get(name, {}).get(f):
                return self._prev[name][f]
            slot = self._slot(it, f)
            if slot is None:
                raise BackendNotFound(f"field {f!r} not found on item {item!r}")
            v = self._read(slot)
            return v.strip() if f == "notes" else v

    def put(self, item, field, value, create=False, keep_previous=False, meta=None):
        check_item_args(item, value)
        if field in RESERVED_FIELDS:
            raise BackendInvalid(f"field {field!r} is reserved")
        meta = clean_meta(meta) if meta is not None else None
        with self._lock:
            existing = lookup_name(self._items, item)
            if create:
                if existing is not None:
                    raise BackendConflict(f"item {item!r} already exists")
                f = "notes" if field in AUTO_ALIASES else field
                if f == "private_key" and not (meta or {}).get("ssh_public_key"):
                    raise BackendInvalid("an SSH key item needs its public key")
                kind = {"password": LOGIN, "private_key": SSH_KEY}.get(f, NOTE)
                new = Item(item, kind, meta=meta, public_key=(meta or {}).get("ssh_public_key"))
                if kind == NOTE and f != "notes":
                    new.fields[f] = value
                else:
                    setattr(new, f, value)
                self._items[item] = new
                return
            it = self._items[self._find(item)]
            f = it.auto_field() if field in AUTO_ALIASES else field
            slot = self._slot(it, f)
            if slot is None:
                raise BackendNotFound(f"field {f!r} not found on item {item!r}")
            old = self._read(slot)
            if keep_previous and old:
                self._prev[it.name] = {"previous_value": old, "previous_replaced_at": now_iso()}
            obj, key = slot
            if isinstance(obj, dict):
                obj[key] = value
            else:
                setattr(obj, key, value)
            if meta is not None:
                it.meta = meta

    def catalog(self):
        with self._lock:
            rows = []
            for name, it in self._items.items():
                if it.meta is not None:
                    rows.append({"item": name, "meta": clean_meta(it.meta)})
                elif auto_shape(it):
                    rows.append({"item": name, "meta": None, "auto": auto_shape(it)})
            return rows

    def set_meta(self, item, meta):
        meta = clean_meta(meta)
        with self._lock:
            self._items[self._find(item)].meta = meta

    def delete(self, item):
        with self._lock:
            key = lookup_name(self._items, item)
            if key is not None:
                self._items.pop(key)
                self._prev.pop(key, None)

    def create_login(self, item, username, password, uri=None, notes=None, meta=None):
        with self._lock:
            if lookup_name(self._items, item) is not None:
                raise BackendConflict(f"item {item!r} already exists")
            self._items[item] = Item(item, LOGIN, username, password, notes or None,
                                     [uri] if uri else [], meta=clean_meta(meta) if meta else None)

    def edit_item(self, item, new_name=None, meta=None, drop_meta=False):
        with self._lock:
            it = self._items[self._find(item)]
            if new_name:
                if lookup_name(self._items, new_name) is not None:
                    raise BackendConflict(f"item {new_name!r} already exists")
                self._items = {(new_name if k == it.name else k): v for k, v in self._items.items()}
                it.name = new_name
            if drop_meta:
                it.meta = None
            if meta is not None:
                it.meta = clean_meta(meta)

    def export_items(self):
        with self._lock:
            return [Item.from_dict(n, it.to_dict()) for n, it in self._items.items()]

    def import_items(self, items, overwrite=False):
        items = [i.validate() for i in items]
        with self._lock:
            clash = [i.name for i in items if i.name in self._items]
            if clash and not overwrite:
                raise BackendConflict(f"item {clash[0]!r} already exists")
            for i in items:
                self._items[i.name] = Item.from_dict(i.name, i.to_dict())
        return [i.name for i in items]


SPEC = BackendSpec("memory", lambda b: MemoryBackend(), lambda b: None,
                   "In-memory, nothing persists; tests and embedding. No keys.")

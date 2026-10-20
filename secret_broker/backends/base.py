"""The backend contract: what the broker core needs from a place that stores secrets.

The core depends ONLY on this module. Bitwarden, the encrypted local store and
the test backends are implementations of `VaultBackend`; nothing outside their
own modules may assume a product (organizations, collections, item type
numbers, a CLI, a server). docs/reference.md ("Backend contract") is the
long-form version; tests/backend_contract.py is the acceptance test.

Vocabulary
----------
item        a named record (a "login", a "note" or an "ssh_key"). Names are
            case-sensitive but looked up leniently (see `get`).
field       one value inside an item: `password`, `username`, `notes`,
            `private_key`, or a custom field name. `None`, `""` and `"auto"`
            all mean "the item's natural secret": password for a login, notes
            for a note, private_key for an ssh_key.
meta        the item's broker metadata: a JSON object (nested objects allowed)
            stored next to the item under the reserved field name `broker`.

Rules every implementation follows
----------------------------------
* Thread safety: every public method may be called from many threads at once.
  A write is atomic (all or nothing) and a successful write is visible to the
  next read from any thread, and to a re-opened backend on the same storage.
* No secret in an exception: messages and `__cause__` text name items and
  fields, never values, keys, passwords or tokens (the broker logs them).
* Failures are `BackendError` or a subclass; never a bare KeyError/OSError.
* Methods never print or log values.
"""
import abc
import dataclasses
import json
import time
from typing import Any, Dict, List, Optional, TypedDict


# -- errors --------------------------------------------------------------------
class BackendError(Exception):
    """Any backend failure. The message is safe to log and to show an operator."""


class BackendRateLimited(BackendError):
    """The store throttled us (HTTP 429, "too many requests"). Transient: retry later."""


class BackendUnavailable(BackendError):
    """The store cannot be reached or opened right now: server down, timeout, wrong
    or missing key, corrupt file. The broker stays up and retries on the next use."""


class BackendConflict(BackendError):
    """The change collides with the current state: the item already exists
    (`put(create=True)`), or the store changed under us."""


class BackendNotFound(BackendError):
    """No such item, or no such field on an item."""


class BackendInvalid(BackendError):
    """The request itself is malformed or forbidden: a reserved field name, a value
    that is not a string, a metadata value that is not an object, ambiguous names."""


class NotSupported(BackendError):
    """The backend does not implement this optional capability (see `capabilities`)."""


class BackendConfigError(ValueError):
    """Bad `backend` settings; the message names the offending field."""


_RATE = ("too many requests", "rate limit", "rate-limit", "429", "throttl")
_UNAVAILABLE = ("timed out", "timeout", "connection", "unavailable", "unreachable",
                "502", "503", "504", "bad gateway", "temporarily", "not running",
                "refused", "no route", "name resolution")
_CONFLICT = ("conflict", "409", "out of date", "outdated", "revision", "modified")
_INVALID = ("not found", "invalid", "400", "bad request", "no rights", "ambiguous")


def error_class(exc):
    """A coarse, stable class for a failure: rate_limited | backend_unavailable |
    conflict | invalid | other. Typed `BackendError`s decide by their class; anything
    else (a foreign exception, or a plain BackendError from an older backend) falls
    back to its text. Only this class should be kept or shown, never the text."""
    if isinstance(exc, BackendRateLimited):
        return "rate_limited"
    if isinstance(exc, BackendUnavailable):
        return "backend_unavailable"
    if isinstance(exc, BackendConflict):
        return "conflict"
    if isinstance(exc, (BackendNotFound, BackendInvalid, NotSupported)):
        return "invalid"
    if isinstance(exc, (KeyError, ValueError)):
        return "invalid"
    msg = str(exc).lower()
    if any(t in msg for t in _RATE):
        return "rate_limited"
    if (isinstance(exc, (TimeoutError, ConnectionError)) or any(t in msg for t in _UNAVAILABLE)):
        return "backend_unavailable"
    if any(t in msg for t in _CONFLICT):
        return "conflict"
    if any(t in msg for t in _INVALID):
        return "invalid"
    return "other"


# -- names ---------------------------------------------------------------------
# Every secret the broker may hand out is an item carrying its metadata under
# this reserved field name. Its value is a JSON object: allowed_hosts, vars,
# approval, ... The store is the catalog; there is no separate config file.
META_FIELD = "broker"
# Fields only the broker writes (rotation history). Readable with `get`, never
# writable through `put`, never offered for adoption.
PREVIOUS_FIELDS = ("previous_value", "previous_replaced_at")
RESERVED_FIELDS = (META_FIELD,) + PREVIOUS_FIELDS
AUTO_ALIASES = (None, "", "auto")

# -- capabilities ---------------------------------------------------------------
CAP_SET_META = "set_meta"           # set_meta persists (policy edits, standing approvals...)
CAP_CREATE_LOGIN = "create_login"
CAP_EDIT_ITEM = "edit_item"
CAP_WARM = "warm"
CAP_ON_EVENT = "on_event"
CAP_ADOPTS = "adopts"
CAP_EXPORT_ITEMS = "export_items"
CAP_IMPORT_ITEMS = "import_items"
KNOWN_CAPABILITIES = frozenset({CAP_SET_META, CAP_CREATE_LOGIN, CAP_EDIT_ITEM, CAP_WARM,
                                CAP_ON_EVENT, CAP_ADOPTS, CAP_EXPORT_ITEMS, CAP_IMPORT_ITEMS})


# -- the neutral item model ------------------------------------------------------
LOGIN, NOTE, SSH_KEY = "login", "note", "ssh_key"
KINDS = (LOGIN, NOTE, SSH_KEY)


@dataclasses.dataclass
class Item:
    """A backend-neutral item: what adoption, import and export speak.

    kind      login | note | ssh_key (cards, identities and the like are not items)
    username/password   a login's credentials (None when absent)
    notes     free text (a note's body; a login's comment)
    uris      a login's URLs
    fields    custom text fields {name: value}, never including the reserved names
    meta      the broker metadata object, or None
    private_key/public_key   an ssh_key item's key pair (OpenSSH text)

    Contains secret values: never log an Item or put one in an exception.
    """
    name: str
    kind: str = NOTE
    username: Optional[str] = None
    password: Optional[str] = None
    notes: Optional[str] = None
    uris: List[str] = dataclasses.field(default_factory=list)
    fields: Dict[str, str] = dataclasses.field(default_factory=dict)
    meta: Optional[dict] = None
    private_key: Optional[str] = None
    public_key: Optional[str] = None

    def __repr__(self):         # never show values
        return f"Item({self.name!r}, {self.kind})"

    def validate(self):
        if not isinstance(self.name, str) or not self.name:
            raise BackendInvalid("item name must be a non-empty string")
        if self.kind not in KINDS:
            raise BackendInvalid(f"item kind must be one of {list(KINDS)}")
        for what, v in (("username", self.username), ("password", self.password),
                        ("notes", self.notes), ("private_key", self.private_key),
                        ("public_key", self.public_key)):
            if v is not None and not isinstance(v, str):
                raise BackendInvalid(f"{what} must be a string")
        if (not isinstance(self.uris, list) or not all(isinstance(u, str) for u in self.uris)
                or not isinstance(self.fields, dict)
                or not all(isinstance(k, str) and isinstance(v, str) for k, v in self.fields.items())):
            raise BackendInvalid("uris must be a list of strings and fields a {name: string} object")
        for k in self.fields:
            if not k or k in RESERVED_FIELDS:
                raise BackendInvalid(f"field name {k!r} is not allowed")
        if self.meta is not None:
            self.meta = clean_meta(self.meta)
        return self

    def to_dict(self):
        """The storage form (also what the local store keeps). `broker` holds meta."""
        d = {"type": self.kind, "notes": self.notes, "uris": list(self.uris),
             "fields": dict(self.fields)}
        if self.kind == LOGIN:
            d.update(username=self.username, password=self.password)
        if self.kind == SSH_KEY:
            d.update(private_key=self.private_key, public_key=self.public_key)
        if self.meta is not None:
            d[META_FIELD] = clean_meta(self.meta)
        return d

    @classmethod
    def from_dict(cls, name, d):
        kind = d.get("type") if d.get("type") in KINDS else NOTE
        meta = d.get(META_FIELD)
        return cls(name=name, kind=kind, username=d.get("username"), password=d.get("password"),
                   notes=d.get("notes"), uris=[u for u in d.get("uris") or [] if u],
                   fields={k: v for k, v in (d.get("fields") or {}).items()
                           if isinstance(v, str)},
                   meta=meta if isinstance(meta, dict) else None,
                   private_key=d.get("private_key"), public_key=d.get("public_key"))

    def auto_field(self):
        return auto_field_for(self.kind)

    def shape(self):
        return auto_shape(self)


def auto_field_for(kind):
    return {LOGIN: "password", SSH_KEY: "private_key"}.get(kind, "notes")


class AutoShape(TypedDict, total=False):
    """What an item without broker metadata could offer: shapes only, never values.

    A login or note:  {"login": bool (a login, not a note), "username": bool,
                       "password": bool, "notes": bool, "fields": [custom field
                       names that hold a value], "uris": [urls]}
    An ssh_key:       {"ssh_public_key": "ssh-ed25519 AAAA..."} (public half only)
    """
    login: bool
    username: bool
    password: bool
    notes: bool
    fields: List[str]
    uris: List[str]
    ssh_public_key: str


class CatalogRow(TypedDict, total=False):
    """One catalog row. `item` is the name; `meta` the parsed broker metadata object
    or None; `auto` (adopted rows only, meta is then None) is an AutoShape."""
    item: str
    meta: Optional[dict]
    auto: AutoShape


def auto_shape(item):
    """The AutoShape of an `Item`, or None when it offers nothing usable (an empty
    login, a note with no text, an ssh key without both halves)."""
    if item.kind == SSH_KEY:
        pub = (item.public_key or "").strip()
        return {"ssh_public_key": pub} if item.private_key and pub else None
    login = item.kind == LOGIN
    info = {"login": login, "username": bool(login and item.username),
            "password": bool(login and item.password), "notes": bool(item.notes),
            "fields": [n for n, v in item.fields.items() if n and v and n not in RESERVED_FIELDS],
            "uris": [u for u in item.uris if u]}
    usable = (info["username"] or info["password"] or info["fields"]
              or (info["notes"] and not info["login"]))
    return info if usable else None


def catalog_rows(pairs):
    """[(item name, raw JSON text or dict or None)] -> explicit CatalogRows; items
    with no metadata are skipped (adoption is the backend's job)."""
    out = []
    for item, raw in pairs:
        if not raw:
            continue
        if isinstance(raw, dict):
            meta = raw
        else:
            try:
                meta = json.loads(raw)
            except ValueError:
                meta = None
        out.append({"item": item, "meta": meta if isinstance(meta, dict) else None})
    return out


def clean_meta(meta):
    """A JSON round-trip copy of `meta`; BackendInvalid unless it is an object."""
    if not isinstance(meta, dict):
        raise BackendInvalid("broker metadata must be an object")
    try:
        return json.loads(json.dumps(meta))
    except (TypeError, ValueError):
        raise BackendInvalid("broker metadata must be JSON-serializable") from None


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclasses.dataclass(frozen=True)
class BackendSpec:
    """How the broker builds a backend from the `backend` settings block.

    name      the `backend.type` value
    validate  validate(cfg) raises BackendConfigError (a ValueError) naming the bad
              field (`backend.path: ...`); never opens files or connects
    build     build(cfg) -> VaultBackend; may open files (a key, a password)
    doc       one line for error messages and docs
    """
    name: str
    build: Any
    validate: Any
    doc: str = ""


# -- the contract ------------------------------------------------------------------
class VaultBackend(abc.ABC):
    """What the broker needs from a secret store.

    Required methods (abstract): get, put, catalog, set_meta, delete.
    Optional behavior is declared in `capabilities` (a frozenset of the CAP_*
    names) and has a safe default here that raises `NotSupported`, so callers
    check `"create_login" in backend.capabilities` and never probe attributes.

    `kind` is a short stable type name ("bw", "local", ...) shown by /v1/status.
    """
    kind = "custom"
    capabilities = frozenset()

    # -- required ----------------------------------------------------------------
    @abc.abstractmethod
    def get(self, item, field):
        """The value of `field` on `item` as a string ("" for a present but empty value).

        Lookup: the exact item name; else the one item whose name matches
        case-insensitively; two such items raise BackendInvalid ("more than one").
        `field` aliases `None`/`""`/`"auto"` mean the item's natural secret (see
        `auto_field_for`). `previous_value` / `previous_replaced_at` are readable
        once a `put(keep_previous=True)` has replaced a value. A note's `notes`
        value has surrounding whitespace removed. Raises BackendNotFound for a
        missing item or field, BackendInvalid for the reserved `broker` field,
        BackendUnavailable when the store cannot be opened. Opens the store on
        demand (unlock, sync, decrypt).
        """

    @abc.abstractmethod
    def put(self, item, field, value, create=False, keep_previous=False, meta=None):
        """Create an item, or replace one field of an existing item.

        create=True: make a new item holding `value` in `field` and (optionally)
        `meta`, in ONE atomic write. The field decides the kind: `password` makes a
        login, `notes` (or auto) a note, `private_key` an ssh_key (needs
        `meta["ssh_public_key"]`), anything else a note with that custom field.
        BackendConflict if the item already exists.
        create=False: replace the value of an existing field (BackendNotFound if
        the item or field is missing). keep_previous=True first copies the old
        non-empty value to `previous_value` and the time to
        `previous_replaced_at`. `meta`, if given, replaces the item's metadata.
        `broker` and the previous_* names are reserved: BackendInvalid.
        `value` must be a str (BackendInvalid otherwise). The value never
        appears in an error.
        """

    @abc.abstractmethod
    def catalog(self):
        """list[CatalogRow]: one row per item that carries metadata
        ({"item", "meta"}, meta None when the stored text is not an object), and,
        when "adopts" is a capability, one row per login/note/ssh_key without
        metadata ({"item", "meta": None, "auto": AutoShape}) that offers something
        usable. Shapes only, never values. Sees current state (refreshes stale
        caches). Items of other kinds (cards, identities) and items outside the
        backend's own scope are never listed. Raises BackendUnavailable when the
        store cannot be read; the broker then keeps its previous catalog.
        """

    @abc.abstractmethod
    def set_meta(self, item, meta):
        """Replace the item's broker metadata with `meta` (a JSON object, nested
        objects preserved exactly). BackendNotFound if the item is missing,
        BackendInvalid if `meta` is not an object. Only meaningful with the
        "set_meta" capability; a backend that cannot persist metadata raises
        NotSupported and omits the capability, so policy edits are refused."""

    @abc.abstractmethod
    def delete(self, item):
        """Permanently remove the item. Deleting a missing item is not an error."""

    # -- optional, declared in `capabilities` ---------------------------------------
    def create_login(self, item, username, password, uri=None, notes=None, meta=None):
        """["create_login"] Create a login with real username, password and URL.
        BackendConflict if the item exists."""
        raise NotSupported("this backend cannot create logins")

    def edit_item(self, item, new_name=None, meta=None, drop_meta=False):
        """["edit_item"] Rename an item and/or replace (`meta`) or remove
        (`drop_meta`) its metadata. BackendConflict if `new_name` exists,
        BackendNotFound if `item` does not."""
        raise NotSupported("this backend cannot edit items")

    def warm(self):
        """["warm"] Open the store ahead of a likely read (unlock, sync, decrypt) so
        the first real read is fast. Called from a background thread; may raise
        BackendUnavailable, which the caller logs and ignores."""
        raise NotSupported("this backend has nothing to warm")

    def close(self):
        """Release resources and drop any unlocked state (lock, stop helper
        processes). Always safe to call, any number of times, from any thread;
        the backend reopens on next use. The default does nothing."""

    def export_items(self):
        """["export_items"] Every login/note/ssh_key in scope as `Item`s WITH values
        (for migration). Callers must treat the result as secret."""
        raise NotSupported("this backend cannot export items")

    def import_items(self, items, overwrite=False):
        """["import_items"] Write whole `Item`s in one atomic change; returns the
        names written. BackendConflict for an existing name unless `overwrite`."""
        raise NotSupported("this backend cannot import items")

    # -- the audit hook ---------------------------------------------------------------
    @property
    def on_event(self):
        """["on_event"] A callback `fn(name, **fields)` the backend calls for audit
        events (store_unlocked, backend_closed, ...). Fields are names, counts and
        reasons, never values. Assign None to detach. A raising callback is
        ignored. Backends that never emit leave it unused."""
        return getattr(self, "_on_event", None)

    @on_event.setter
    def on_event(self, fn):
        self._on_event = fn

    def _emit(self, name, **fields):
        fn = self.on_event
        if fn:
            try:
                fn(name, **fields)
            except Exception:  # noqa: BLE001 - an audit hook must never break a read
                pass

    def supports(self, capability):
        return capability in self.capabilities


_UNSET = object()


def check_item_args(item, value=_UNSET):
    """Shared argument checks for get/put implementations: a non-empty str name and,
    when `value` is given, a str value (None is not a value)."""
    if not isinstance(item, str) or not item:
        raise BackendInvalid("item name must be a non-empty string")
    if value is not _UNSET and not isinstance(value, str):
        raise BackendInvalid("value must be a string")


def lookup_name(names, wanted):
    """The contract's lookup rule on any iterable of names: exact match, else the
    one case-insensitive match, else None; two case-insensitive matches raise
    BackendInvalid. Returns the stored name."""
    names = list(names)
    if wanted in names:
        return wanted
    low = [k for k in names if k.lower() == str(wanted).lower()]
    if len(low) > 1:
        raise BackendInvalid(f"More than one item is named {wanted!r}")
    return low[0] if low else None

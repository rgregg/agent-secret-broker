"""Bitwarden / Vaultwarden backends, through the `bw` CLI or one long-lived `bw serve`.

Everything Bitwarden-specific lives here: organization and collection scoping,
item type numbers, the `bw` process handling, `serve`, `prewarm`. The broker core
sees only the `VaultBackend` contract (base.py)."""
import json
import os
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .. import destguard

from .. import sshkey
from .base import (CAP_ADOPTS, CAP_CREATE_LOGIN, CAP_EDIT_ITEM, CAP_EXPORT_ITEMS, CAP_ON_EVENT,
                   CAP_SET_META, CAP_WARM, LOGIN, META_FIELD, NOTE, RESERVED_FIELDS, SSH_KEY,
                   BackendConfigError, BackendConflict, BackendError, BackendInvalid,
                   BackendNotFound, BackendRateLimited, BackendSpec, BackendUnavailable, Item,
                   VaultBackend, AUTO_ALIASES, auto_shape, catalog_rows, check_item_args,
                   clean_meta, error_class, now_iso)

_RESERVED_FIELDS = RESERVED_FIELDS      # kept for older imports


def _bw_error(message):
    """The BackendError subclass that matches what `bw` / `bw serve` said."""
    cls = error_class(BackendError(message))
    low = message.lower()
    if cls == "rate_limited":
        return BackendRateLimited(message)
    if cls == "backend_unavailable":
        return BackendUnavailable(message)
    if cls == "conflict":
        return BackendConflict(message)
    if cls == "invalid":
        return BackendNotFound(message) if "not found" in low else BackendInvalid(message)
    return BackendError(message)


def _to_item(it):
    """A Bitwarden item object -> neutral `Item` (with values), or None for kinds the
    broker never serves (cards, identities)."""
    if it.get("type") == 5:                 # Bitwarden's native SSH key item
        sk = it.get("sshKey") or {}
        return Item(it.get("name") or "", SSH_KEY, private_key=sk.get("privateKey"),
                    public_key=sk.get("publicKey"))
    if it.get("type") not in (1, 2):
        return None
    login = it.get("login") or {}
    is_login = it.get("type") == 1
    return Item(it.get("name") or "", LOGIN if is_login else NOTE,
                username=login.get("username") if is_login else None,
                password=login.get("password") if is_login else None,
                notes=it.get("notes"),
                uris=[u["uri"] for u in login.get("uris") or [] if u.get("uri")],
                fields={f["name"]: f["value"] for f in it.get("fields") or []
                        if f.get("name") and f.get("value") and f.get("type") in (0, 1)})


def _auto_info(it):
    """What an item without broker metadata could offer: shapes only, never values.
    None when it has nothing usable (or is not a login, secure note or SSH key)."""
    item = _to_item(it)
    return auto_shape(item) if item is not None else None


class BwBackend(VaultBackend):
    """Bitwarden/Vaultwarden via the `bw` CLI.

    Logs in with an API key (BW_CLIENTID/BW_CLIENTSECRET) and unlocks with the
    master password on demand. The session is kept for `idle_timeout` seconds
    after its last use, then logged out, so the vault is open only around real
    use but a run of approvals stays fast. Thread-safe, and safe to call when
    `bw` is already logged in/unlocked (its on-disk state can outlive us).
    """

    kind = "bw"

    def __init__(self, server_url, master_password_file, bw="bw", sync_interval=300,
                 idle_timeout=300, organization=None, collection=None, prewarm=True):
        caps = {CAP_SET_META, CAP_CREATE_LOGIN, CAP_EDIT_ITEM, CAP_ON_EVENT, CAP_EXPORT_ITEMS}
        if prewarm:
            caps.add(CAP_WARM)              # `backend.prewarm: false` turns request-time unlock off
        if organization and collection:
            caps.add(CAP_ADOPTS)            # cannot scope adoption without both: adopt nothing
        self.capabilities = frozenset(caps)
        self._bw = bw
        self._org_want, self._coll_want = organization, collection
        self._target_ids = None
        self._server_url = server_url
        with open(master_password_file) as f:
            self._pw = f.read().strip()
        self._session = None
        self._sync_interval = sync_interval
        self._synced = 0.0
        self._idle_timeout = idle_timeout
        self._last_used = 0.0
        self._timer = None
        self._lock = threading.Lock()

    # -- plumbing ---------------------------------------------------------
    def _run(self, *args, env_extra=None, stdin=None):
        env = dict(os.environ, **(env_extra or {}))
        try:
            p = subprocess.run([self._bw, *args], env=env, capture_output=True, text=True,
                               timeout=60, input=stdin)
        except subprocess.TimeoutExpired:
            raise BackendUnavailable(f"bw {args[0]} timed out") from None
        except OSError as e:
            raise BackendUnavailable(f"cannot run {self._bw}: {e.strerror}") from None
        if p.returncode != 0:
            raise _bw_error(f"bw {args[0]} failed: {p.stderr.strip()[:200]}")
        return p.stdout.strip()

    def _status(self):
        return json.loads(self._run("status"))["status"]

    def _unlock(self):
        status = self._status()
        if status == "unauthenticated":
            self._run("config", "server", self._server_url)
            self._run("login", "--apikey")
        elif status == "unlocked":
            # an unlocked vault from another process has a session key we cannot know
            self._run("lock")
        self._session = self._run("unlock", "--passwordenv", "BW_MASTER_PW", "--raw",
                                  env_extra={"BW_MASTER_PW": self._pw})

    def _sync(self):
        self._run("sync", "--session", self._session)
        self._synced = time.time()

    def _fetch(self, item):
        # sync is slow, so only re-sync periodically (or after a retry reset)
        if time.time() - self._synced > self._sync_interval:
            self._sync()
        return json.loads(self._run("get", "item", item, "--session", self._session))

    # -- primitives that BwServeBackend replaces -----------------------------
    def _list_orgs(self):
        return json.loads(self._run("list", "organizations", "--session", self._session))

    def _list_collections(self, org):
        return json.loads(self._run("list", "collections", "--organizationid", org,
                                    "--session", self._session))

    def _delete_item(self, item_id):
        self._run("delete", "item", item_id, "--permanent", "--session", self._session)

    def _logout(self):
        self._run("logout")

    # -- idle logout ------------------------------------------------------
    def _touch(self):
        """Call with the lock held after a successful use: (re)arm the idle timer."""
        self._last_used = time.monotonic()
        if self._timer is not None:
            self._timer.cancel()
        if self._idle_timeout and self._idle_timeout > 0:
            self._timer = threading.Timer(self._idle_timeout, self._idle_logout)
            self._timer.daemon = True
            self._timer.start()

    def _idle_logout(self):
        with self._lock:
            if self._session is None:
                return
            if time.monotonic() - self._last_used < self._idle_timeout - 0.05:
                return              # used again since this timer was armed
            try:
                self._logout()
            except BackendError:
                pass
            self._session, self._synced, self._timer = None, 0.0, None
        self._emit("backend_closed", idle_seconds=self._idle_timeout)

    def close(self):
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            if self._session is not None:
                try:
                    self._logout()
                except BackendError:
                    pass
            self._session, self._synced, self._timer = None, 0.0, None

    # -- writes -----------------------------------------------------------
    def _find(self, item):
        """Fresh lookup by exact name. None if absent; raises if ambiguous/other."""
        self._synced = 0.0                      # uniqueness checks must see current state
        for attempt in (1, 2):
            try:
                if self._session is None:
                    self._unlock()
                return self._fetch(item)
            except BackendError as e:
                if isinstance(e, BackendNotFound) or "not found" in str(e).lower():
                    return None
                if attempt == 2:
                    raise
                self._session, self._synced = None, 0.0

    def _resolve_target(self):
        """(organization id, collection id) that new items are created in."""
        if self._target_ids:
            return self._target_ids
        orgs = self._list_orgs()
        if self._org_want:
            orgs = [o for o in orgs if self._org_want in (o["id"], o["name"])]
        if len(orgs) != 1:
            raise BackendInvalid("cannot choose an organization; set backend.organization")
        org = orgs[0]["id"]
        colls = self._list_collections(org)
        if self._coll_want:
            colls = [c for c in colls if self._coll_want in (c["id"], c["name"])]
        if len(colls) != 1:
            raise BackendInvalid("cannot choose a collection; set backend.collection")
        self._target_ids = (org, colls[0]["id"])
        return self._target_ids

    @staticmethod
    def _template(item, field, value, org, coll, meta=None):
        obj = BwBackend._template_base(item, field, value, org, coll, meta)
        if meta is not None:
            BwBackend._with_meta(obj, meta)
        return obj

    @staticmethod
    def _with_meta(obj, meta):
        fields = [f for f in (obj.get("fields") or []) if f.get("name") != META_FIELD]
        fields.append({"name": META_FIELD, "value": json.dumps(meta, separators=(",", ":")), "type": 0})
        obj["fields"] = fields

    @staticmethod
    def _template_base(item, field, value, org, coll, meta=None):
        base = {"organizationId": org, "collectionIds": [coll], "folderId": None,
                "favorite": False, "name": item, "reprompt": 0}
        if field == "private_key":
            # a real Bitwarden SSH key item (type 5), so the Bitwarden apps and
            # their SSH agent see it as one; the public half comes with the request
            pub = (meta or {}).get("ssh_public_key")
            if not pub:
                raise BackendInvalid("an SSH key item needs its public key")
            return {**base, "type": 5, "notes": None,
                    "sshKey": {"privateKey": value, "publicKey": pub,
                               "keyFingerprint": sshkey.fingerprint(sshkey.blob_from_line(pub))}}
        if field == "password":
            return {**base, "type": 1, "notes": None,
                    "login": {"username": None, "password": value, "uris": []}}
        if field == "notes":
            return {**base, "type": 2, "secureNote": {"type": 0}, "notes": value}
        return {**base, "type": 2, "secureNote": {"type": 0}, "notes": None,
                "fields": [{"name": field, "value": value, "type": 1}]}

    @staticmethod
    def _auto_field(obj):
        """The natural secret field of an item: an SSH key's private key, a
        login's password, else the note."""
        if obj.get("sshKey") is not None:
            return "private_key"
        return "password" if obj.get("login") is not None else "notes"

    @staticmethod
    def _apply(obj, field, value, keep_previous):
        old = None
        if field in (None, "", "auto"):
            field = BwBackend._auto_field(obj)
        if field == "password" and obj.get("login") is not None:
            old = obj["login"].get("password")
            obj["login"]["password"] = value
        elif field == "private_key" and obj.get("sshKey") is not None:
            old = obj["sshKey"].get("privateKey")
            obj["sshKey"]["privateKey"] = value
        elif field == "notes":
            old = obj.get("notes")
            obj["notes"] = value
        else:
            fields = obj.get("fields") or []
            hit = next((f for f in fields if f.get("name") == field), None)
            if hit is None:
                raise BackendNotFound(f"field {field!r} not found on item {obj.get('name')!r}")
            old, hit["value"] = hit.get("value"), value
        if keep_previous and old:
            fields = [f for f in (obj.get("fields") or [])
                      if f.get("name") not in ("previous_value", "previous_replaced_at")]
            fields.append({"name": "previous_value", "value": old, "type": 1})
            fields.append({"name": "previous_replaced_at", "type": 0, "value": now_iso()})
            obj["fields"] = fields

    def _submit(self, verb, obj, item_id=None):
        # JSON goes to `bw encode` and `bw create/edit` over stdin: the value is
        # never on a command line.
        enc = self._run("encode", stdin=json.dumps(obj))
        args = [verb, "item"] + ([item_id] if item_id else []) + ["--session", self._session]
        return self._run(*args, stdin=enc)

    def put(self, item, field, value, create=False, keep_previous=False, meta=None):
        """Create a new item (with its broker metadata), or replace one field of
        an existing item."""
        check_item_args(item, value)
        if field == META_FIELD:
            raise BackendInvalid("the broker metadata field cannot hold a secret")
        if field in _RESERVED_FIELDS:
            raise BackendInvalid(f"field {field!r} is reserved")
        if meta is not None:
            meta = clean_meta(meta)
        if create and field in AUTO_ALIASES:
            field = "notes"
        with self._lock:
            try:
                self._put_locked(item, field, value, create, keep_previous, meta)
            except BackendError as e:
                msg = str(e).lower()
                if (isinstance(e, (BackendNotFound, BackendConflict, BackendInvalid))
                        or any(t in msg for t in ("already exists", "not found", "no rights",
                                                  "ambiguous", "more than one"))):
                    raise
                # the session may have been invalidated behind our back (another
                # bw process on the same state dir): start clean once and retry
                self._session, self._synced, self._target_ids = None, 0.0, None
                self._put_locked(item, field, value, create, keep_previous, meta)

    def _put_locked(self, item, field, value, create, keep_previous, meta=None):
        existing = self._find(item)
        if create:
            if existing is not None:
                raise BackendConflict(f"item {item!r} already exists")
            org, coll = self._resolve_target()
            self._submit("create", self._template(item, field, value, org, coll, meta))
        else:
            if existing is None:
                raise BackendNotFound(f"item {item!r} not found")
            self._apply(existing, field, value, keep_previous)
            if meta is not None:
                self._with_meta(existing, meta)
            self._submit("edit", existing, existing["id"])
        self._synced = 0.0
        self._touch()

    # -- catalog ----------------------------------------------------------
    def _list_items(self):
        return json.loads(self._run("list", "items", "--session", self._session))

    def catalog(self):
        """[{"item", "meta"}] for every item that carries broker metadata, plus
        [{"item", "meta": None, "auto": shape}] for the other logins and secure
        notes in the broker's own collection (they are adopted with defaults;
        nothing outside that collection ever is). Sees current state (it syncs if
        the cache is old)."""
        with self._lock:
            for attempt in (1, 2):
                try:
                    if self._session is None:
                        self._unlock()
                    if time.time() - self._synced > self._sync_interval:
                        self._sync()
                    items = self._list_items()
                    break
                except BackendError:
                    if attempt == 2:
                        raise
                    self._session, self._synced = None, 0.0
            target = None
            if self._org_want and self._coll_want:       # cannot scope without both: adopt nothing
                try:
                    target = self._resolve_target()
                except BackendError:
                    target = None
            self._touch()
        rows = []
        for it in items:
            raw = next((f.get("value") for f in it.get("fields") or []
                        if f.get("name") == META_FIELD), None)
            if raw:
                rows.extend(catalog_rows([(it["name"], raw)]))
            elif (target and it.get("organizationId") == target[0]
                  and target[1] in (it.get("collectionIds") or [])):
                info = _auto_info(it)
                if info:
                    rows.append({"item": it["name"], "meta": None, "auto": info})
        return rows

    def set_meta(self, item, meta):
        """Replace the broker metadata of an existing item."""
        check_item_args(item)
        meta = clean_meta(meta)
        with self._lock:
            existing = self._find(item)
            if existing is None:
                raise BackendNotFound(f"item {item!r} not found")
            self._with_meta(existing, meta)
            self._submit("edit", existing, existing["id"])
            self._synced = 0.0
            self._touch()

    def create_login(self, item, username, password, uri=None, notes=None, meta=None):
        """Create a Login item with real username / password / URL fields."""
        with self._lock:
            if self._find(item) is not None:
                raise BackendConflict(f"item {item!r} already exists")
            org, coll = self._resolve_target()
            obj = BwBackend._template_base(item, "password", password, org, coll)
            obj["login"]["username"] = username
            obj["login"]["uris"] = [{"match": None, "uri": uri}] if uri else []
            obj["notes"] = notes or None
            if meta is not None:
                BwBackend._with_meta(obj, meta)
            self._submit("create", obj)
            self._synced = 0.0
            self._touch()

    def edit_item(self, item, new_name=None, meta=None, drop_meta=False):
        """Rename an item and/or replace or remove its broker metadata."""
        with self._lock:
            existing = self._find(item)
            if existing is None:
                raise BackendNotFound(f"item {item!r} not found")
            if new_name:
                if self._find(new_name) is not None:
                    raise BackendConflict(f"item {new_name!r} already exists")
                existing["name"] = new_name
            if drop_meta:
                existing["fields"] = [f for f in (existing.get("fields") or [])
                                      if f.get("name") != META_FIELD]
            if meta is not None:
                BwBackend._with_meta(existing, meta)
            self._submit("edit", existing, existing["id"])
            self._synced = 0.0
            self._touch()

    def delete(self, item):
        """Permanently delete an item (used to roll back a half-finished create)."""
        check_item_args(item)
        with self._lock:
            existing = self._find(item)
            if existing is None:
                return
            self._delete_item(existing["id"])
            self._synced = 0.0
            self._touch()

    def export_items(self):
        """Every login, secure note and SSH key the broker serves, with values: the
        items in the broker's collection plus any item carrying broker metadata
        (which the catalog would list). For migration; the result is secret."""
        with self._lock:
            for attempt in (1, 2):
                try:
                    if self._session is None:
                        self._unlock()
                    self._sync()
                    items = self._list_items()
                    break
                except BackendError:
                    if attempt == 2:
                        raise
                    self._session, self._synced = None, 0.0
            org, coll = self._resolve_target()
            self._touch()
        out = []
        for it in items:
            raw = next((f.get("value") for f in it.get("fields") or []
                        if f.get("name") == META_FIELD), None)
            in_scope = it.get("organizationId") == org and coll in (it.get("collectionIds") or [])
            if not raw and not in_scope:
                continue
            item = _to_item(it)
            if item is None:
                continue
            item.fields = {k: v for k, v in item.fields.items() if k not in _RESERVED_FIELDS}
            if raw:
                try:
                    meta = json.loads(raw)
                except ValueError:
                    meta = None
                item.meta = meta if isinstance(meta, dict) else None
            out.append(item)
        return out

    # -- public -----------------------------------------------------------
    def warm(self):
        """Unlock and sync ahead of a likely read; extends the idle window."""
        with self._lock:
            if self._session is None:
                self._unlock()
            if time.time() - self._synced > self._sync_interval:
                self._sync()
            self._touch()

    def get(self, item, field):
        check_item_args(item)
        if field == META_FIELD:
            raise BackendInvalid("the broker metadata field is not a secret")
        with self._lock:
            try:
                if self._session is None:
                    self._unlock()
                obj = self._fetch(item)
            except BackendError:
                # stale session / outdated local copy / half-finished earlier
                # attempt: start clean once, with a fresh sync
                self._session, self._synced = None, 0.0
                self._unlock()
                obj = self._fetch(item)
            self._touch()
        if field in (None, "", "auto"):
            field = self._auto_field(obj)
        if field == "private_key" and obj.get("sshKey"):
            return obj["sshKey"].get("privateKey") or ""
        if field == "password" and obj.get("login"):
            return obj["login"]["password"]
        if field == "username" and obj.get("login"):
            return obj["login"]["username"]
        if field == "notes":
            # secure notes are free text; a trailing newline would corrupt a header
            return (obj.get("notes") or "").strip()
        for f in obj.get("fields") or []:
            if f.get("name") == field:
                return f.get("value") or ""
        raise BackendNotFound(f"field {field!r} not found on item {item!r}")


class BwServeBackend(BwBackend):
    """Same behaviour as BwBackend, through one long-lived `bw serve`.

    The CLI backend launches `bw` for every command, and each launch may refresh
    the access token, which Vaultwarden rate-limits like a login. Here a single
    `bw serve` process (127.0.0.1, random port, inside this container) holds the
    unlocked vault, so a request costs a few local HTTP calls and the token is
    refreshed only when it actually expires. Idle logout still locks the vault,
    stops the process and logs out, so nothing stays open between uses.

    Items are looked up by exact name (case-insensitive) or id. The CLI's
    `bw get item NAME` does a substring search, which makes "openai" collide
    with "OpenAI Backup" and "Grafana" ambiguous next to "Grafana Admin".
    """

    def __init__(self, *a, startup_timeout=30, **kw):
        super().__init__(*a, **kw)
        self._proc, self._port = None, None
        self._startup_timeout = startup_timeout

    # -- the serve process ------------------------------------------------
    def _http(self, method, path, body=None, timeout=60):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(f"http://127.0.0.1:{self._port}{path}", data=data, method=method,
                                   headers={"Content-Type": "application/json"})
        try:
            with destguard.operator_urlopen(r, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raw = e.read()
        except OSError as e:
            raise BackendUnavailable(f"bw serve unreachable: {e}") from None
        try:
            out = json.loads(raw)
        except ValueError:
            raise BackendUnavailable(f"bw serve returned a non-JSON reply ({len(raw)} bytes)") from None
        if not out.get("success"):
            raise _bw_error(str(out.get("message") or "bw serve request failed")[:200])
        return out.get("data")

    @staticmethod
    def _free_port():
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _stop_server(self):
        p, self._proc = self._proc, None
        if p is None:
            return
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(5)

    def _owns_port(self):
        """True only if every listener on our port is a socket of our child process."""
        want = set()
        for name in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                rows = open(name).read().splitlines()[1:]
            except OSError:
                continue
            for row in rows:
                f = row.split()
                if len(f) > 9 and f[3] == "0A" and int(f[1].rsplit(":", 1)[1], 16) == self._port:
                    want.add(f[9])
        if not want:
            return False
        mine = set()
        try:
            for fd in os.listdir(f"/proc/{self._proc.pid}/fd"):
                try:
                    link = os.readlink(f"/proc/{self._proc.pid}/fd/{fd}")
                except OSError:
                    continue
                if link.startswith("socket:["):
                    mine.add(link[8:-1])
        except OSError:
            return False
        return want <= mine

    def _start_server(self, session):
        """Start `bw serve` already unlocked. The master password and session key
        never cross the HTTP port: the session goes in the child's environment,
        and nothing is sent until we have confirmed that our child owns the port
        (another local process could otherwise squat on it)."""
        self._stop_server()
        self._port = self._free_port()
        self._proc = subprocess.Popen(
            [self._bw, "serve", "--hostname", "127.0.0.1", "--port", str(self._port)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=dict(os.environ, BW_SESSION=session))
        deadline = time.monotonic() + self._startup_timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise BackendUnavailable("bw serve exited during startup")
            if self._owns_port():
                try:
                    self._http("GET", "/status", timeout=2)
                except BackendError:
                    time.sleep(0.2)
                    continue
                if self._proc.poll() is None and self._owns_port():
                    return
            time.sleep(0.2)
        self._stop_server()
        raise BackendUnavailable("bw serve did not become ready on a port it owns")

    # -- session ------------------------------------------------------------
    def _unlock(self):
        self._stop_server()                       # CLI login must not race a running server
        super()._unlock()                         # login if needed, then unlock -> session key
        key, self._session = self._session, None
        self._start_server(key)
        self._session = "serve"                   # truthy marker: the server holds the key

    def _sync(self):
        self._http("POST", "/sync", timeout=120)
        self._synced = time.time()

    def _logout(self):
        try:
            if self._proc is not None and self._proc.poll() is None:
                self._http("POST", "/lock", timeout=10)
        except BackendError:
            pass
        self._stop_server()
        self._run("logout")

    # -- items --------------------------------------------------------------
    def _fetch(self, item):
        if time.time() - self._synced > self._sync_interval:
            self._sync()
        found = self._http("GET", "/list/object/items?search=" + urllib.parse.quote(item))
        rows = (found or {}).get("data") or []
        exact = [r for r in rows if r.get("name") == item or r.get("id") == item]
        if not exact:
            exact = [r for r in rows if str(r.get("name", "")).lower() == item.lower()]
        if not exact:
            raise BackendNotFound("Not found.")
        if len(exact) > 1:
            raise BackendInvalid(f"More than one item is named {item!r}")
        return self._http("GET", "/object/item/" + urllib.parse.quote(exact[0]["id"]))

    def _list_orgs(self):
        return (self._http("GET", "/list/object/organizations") or {}).get("data") or []

    def _list_items(self):
        return (self._http("GET", "/list/object/items") or {}).get("data") or []

    def _list_collections(self, org):
        path = "/list/object/collections?organizationId=" + urllib.parse.quote(org)
        return (self._http("GET", path) or {}).get("data") or []

    def _submit(self, verb, obj, item_id=None):
        if verb == "create":
            return self._http("POST", "/object/item", obj)
        return self._http("PUT", "/object/item/" + urllib.parse.quote(item_id), obj)

    def _delete_item(self, item_id):
        self._http("DELETE", "/object/item/" + urllib.parse.quote(item_id) + "?permanent=true")


# -- configuration ---------------------------------------------------------------
def _opt_str(b, key):
    v = b.get(key)
    if v is not None and (not isinstance(v, str) or not v):
        raise BackendConfigError(f"backend.{key}: must be a non-empty string")


def validate(b):
    """Bitwarden settings. Unknown keys are ignored, as they always were."""
    for k in ("server_url", "master_password_file"):
        if not isinstance(b.get(k), str) or not b[k]:
            raise BackendConfigError(f"backend.{k}: required (a non-empty string)")
    _opt_str(b, "organization")
    _opt_str(b, "collection")
    idle = b.get("idle_timeout", 300)
    if isinstance(idle, bool) or not isinstance(idle, (int, float)) or idle < 0:
        raise BackendConfigError("backend.idle_timeout: must be a number of seconds >= 0")
    for k in ("serve", "prewarm"):
        if k in b and not isinstance(b[k], bool):
            raise BackendConfigError(f"backend.{k}: must be true or false")


def build(b):
    bw_class = BwServeBackend if b.get("serve") else BwBackend
    return bw_class(b["server_url"], b["master_password_file"],
                    idle_timeout=b.get("idle_timeout", 300),
                    organization=b.get("organization"), collection=b.get("collection"),
                    prewarm=b.get("prewarm", True))


SPEC = BackendSpec(
    name="bw", build=build, validate=validate,
    doc="Bitwarden / Vaultwarden through the bw CLI (serve: true keeps one bw serve). "
        "Keys: server_url, master_password_file, organization, collection, serve, "
        "idle_timeout, prewarm.")

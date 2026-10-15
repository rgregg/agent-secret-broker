"""Secret backends. A backend resolves a (item, field) reference to a string."""
import json
import os
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


class BackendError(Exception):
    pass


class FileBackend:
    """JSON file {item: {field: value}}. For tests and bootstrapping only."""

    def __init__(self, path):
        with open(path) as f:
            self._data = json.load(f)

    def get(self, item, field):
        field = "notes" if field in (None, "", "auto") else field
        try:
            return self._data[item][field]
        except KeyError:
            raise BackendError(f"{item}/{field} not found")

    def put(self, item, field, value, create=False, keep_previous=False):
        if create and item in self._data:
            raise BackendError(f"item {item!r} already exists")
        if not create and item not in self._data:
            raise BackendError(f"item {item!r} not found")
        field = "notes" if field in (None, "", "auto") else field
        rec = self._data.setdefault(item, {})
        if keep_previous and field in rec:
            rec["previous_value"] = rec[field]
        rec[field] = value

    def delete(self, item):
        self._data.pop(item, None)


class BwBackend:
    """Bitwarden/Vaultwarden via the `bw` CLI.

    Logs in with an API key (BW_CLIENTID/BW_CLIENTSECRET) and unlocks with the
    master password on demand. The session is kept for `idle_timeout` seconds
    after its last use, then logged out, so the vault is open only around real
    use but a run of approvals stays fast. Thread-safe, and safe to call when
    `bw` is already logged in/unlocked (its on-disk state can outlive us).
    """

    def __init__(self, server_url, master_password_file, bw="bw", sync_interval=300,
                 idle_timeout=300, organization=None, collection=None):
        self._bw = bw
        self._org_want, self._coll_want = organization, collection
        self._target_ids = None
        self._server_url = server_url
        self._pw = open(master_password_file).read().strip()
        self._session = None
        self._sync_interval = sync_interval
        self._synced = 0.0
        self._idle_timeout = idle_timeout
        self._last_used = 0.0
        self._timer = None
        self._lock = threading.Lock()
        self.on_event = None        # optional callback(name, **fields), e.g. audit

    # -- plumbing ---------------------------------------------------------
    def _run(self, *args, env_extra=None, stdin=None):
        env = dict(os.environ, **(env_extra or {}))
        p = subprocess.run([self._bw, *args], env=env, capture_output=True, text=True, timeout=60,
                           input=stdin)
        if p.returncode != 0:
            raise BackendError(f"bw {args[0]} failed: {p.stderr.strip()[:200]}")
        return p.stdout.strip()

    def _emit(self, name, **fields):
        if self.on_event:
            try:
                self.on_event(name, **fields)
            except Exception:  # noqa: BLE001
                pass

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
                if "not found" in str(e).lower():
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
            raise BackendError("cannot choose an organization; set backend.organization")
        org = orgs[0]["id"]
        colls = self._list_collections(org)
        if self._coll_want:
            colls = [c for c in colls if self._coll_want in (c["id"], c["name"])]
        if len(colls) != 1:
            raise BackendError("cannot choose a collection; set backend.collection")
        self._target_ids = (org, colls[0]["id"])
        return self._target_ids

    @staticmethod
    def _template(item, field, value, org, coll):
        base = {"organizationId": org, "collectionIds": [coll], "folderId": None,
                "favorite": False, "name": item, "reprompt": 0}
        if field == "password":
            return {**base, "type": 1, "notes": None,
                    "login": {"username": None, "password": value, "uris": []}}
        if field == "notes":
            return {**base, "type": 2, "secureNote": {"type": 0}, "notes": value}
        return {**base, "type": 2, "secureNote": {"type": 0}, "notes": None,
                "fields": [{"name": field, "value": value, "type": 1}]}

    @staticmethod
    def _auto_field(obj):
        """The natural secret field of an item: a login's password, else the note."""
        return "password" if obj.get("login") is not None else "notes"

    @staticmethod
    def _apply(obj, field, value, keep_previous):
        old = None
        if field in (None, "", "auto"):
            field = BwBackend._auto_field(obj)
        if field == "password" and obj.get("login") is not None:
            old = obj["login"].get("password")
            obj["login"]["password"] = value
        elif field == "notes":
            old = obj.get("notes")
            obj["notes"] = value
        else:
            fields = obj.get("fields") or []
            hit = next((f for f in fields if f.get("name") == field), None)
            if hit is None:
                raise BackendError(f"field {field!r} not found on item {obj.get('name')!r}")
            old, hit["value"] = hit.get("value"), value
        if keep_previous and old:
            fields = [f for f in (obj.get("fields") or [])
                      if f.get("name") not in ("previous_value", "previous_replaced_at")]
            fields.append({"name": "previous_value", "value": old, "type": 1})
            fields.append({"name": "previous_replaced_at", "type": 0,
                           "value": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            obj["fields"] = fields

    def _submit(self, verb, obj, item_id=None):
        # JSON goes to `bw encode` and `bw create/edit` over stdin: the value is
        # never on a command line.
        enc = self._run("encode", stdin=json.dumps(obj))
        args = [verb, "item"] + ([item_id] if item_id else []) + ["--session", self._session]
        return self._run(*args, stdin=enc)

    def put(self, item, field, value, create=False, keep_previous=False):
        """Create a new item, or replace one field of an existing item."""
        with self._lock:
            try:
                self._put_locked(item, field, value, create, keep_previous)
            except BackendError as e:
                msg = str(e).lower()
                if any(t in msg for t in ("already exists", "not found", "no rights",
                                          "ambiguous", "more than one")):
                    raise
                # the session may have been invalidated behind our back (another
                # bw process on the same state dir): start clean once and retry
                self._session, self._synced, self._target_ids = None, 0.0, None
                self._put_locked(item, field, value, create, keep_previous)

    def _put_locked(self, item, field, value, create, keep_previous):
        existing = self._find(item)
        if create:
            if existing is not None:
                raise BackendError(f"item {item!r} already exists")
            org, coll = self._resolve_target()
            self._submit("create", self._template(item, field, value, org, coll))
        else:
            if existing is None:
                raise BackendError(f"item {item!r} not found")
            self._apply(existing, field, value, keep_previous)
            self._submit("edit", existing, existing["id"])
        self._synced = 0.0
        self._touch()

    def delete(self, item):
        """Permanently delete an item (used to roll back a half-finished create)."""
        with self._lock:
            existing = self._find(item)
            if existing is None:
                return
            self._delete_item(existing["id"])
            self._synced = 0.0
            self._touch()

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
        raise BackendError(f"field {field!r} not found on item {item!r}")


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
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raw = e.read()
        except OSError as e:
            raise BackendError(f"bw serve unreachable: {e}") from None
        try:
            out = json.loads(raw)
        except ValueError:
            raise BackendError(f"bw serve returned a non-JSON reply ({len(raw)} bytes)") from None
        if not out.get("success"):
            raise BackendError(str(out.get("message") or "bw serve request failed")[:200])
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
                raise BackendError("bw serve exited during startup")
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
        raise BackendError("bw serve did not become ready on a port it owns")

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
            raise BackendError("Not found.")
        if len(exact) > 1:
            raise BackendError(f"More than one item is named {item!r}")
        return self._http("GET", "/object/item/" + urllib.parse.quote(exact[0]["id"]))

    def _list_orgs(self):
        return (self._http("GET", "/list/object/organizations") or {}).get("data") or []

    def _list_collections(self, org):
        path = "/list/object/collections?organizationId=" + urllib.parse.quote(org)
        return (self._http("GET", path) or {}).get("data") or []

    def _submit(self, verb, obj, item_id=None):
        if verb == "create":
            return self._http("POST", "/object/item", obj)
        return self._http("PUT", "/object/item/" + urllib.parse.quote(item_id), obj)

    def _delete_item(self, item_id):
        self._http("DELETE", "/object/item/" + urllib.parse.quote(item_id) + "?permanent=true")

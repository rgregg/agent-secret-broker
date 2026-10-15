"""Secret backends. A backend resolves a (item, field) reference to a string."""
import json
import os
import subprocess
import threading
import time


class BackendError(Exception):
    pass


class FileBackend:
    """JSON file {item: {field: value}}. For tests and bootstrapping only."""

    def __init__(self, path):
        with open(path) as f:
            self._data = json.load(f)

    def get(self, item, field):
        try:
            return self._data[item][field]
        except KeyError:
            raise BackendError(f"{item}/{field} not found")


class BwBackend:
    """Bitwarden/Vaultwarden via the `bw` CLI.

    Logs in with an API key (BW_CLIENTID/BW_CLIENTSECRET) and unlocks with the
    master password on demand. The session is kept for `idle_timeout` seconds
    after its last use, then logged out, so the vault is open only around real
    use but a run of approvals stays fast. Thread-safe, and safe to call when
    `bw` is already logged in/unlocked (its on-disk state can outlive us).
    """

    def __init__(self, server_url, master_password_file, bw="bw", sync_interval=300,
                 idle_timeout=300):
        self._bw = bw
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
    def _run(self, *args, env_extra=None):
        env = dict(os.environ, **(env_extra or {}))
        p = subprocess.run([self._bw, *args], env=env, capture_output=True, text=True, timeout=60)
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
                self._run("logout")
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
                    self._run("logout")
                except BackendError:
                    pass
            self._session, self._synced, self._timer = None, 0.0, None

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

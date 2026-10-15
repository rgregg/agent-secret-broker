"""Secret backends. A backend resolves a (item, field) reference to a string."""
import json
import os
import subprocess


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
    master password on first use; the session key is kept in memory only.
    """

    def __init__(self, server_url, master_password_file, bw="bw"):
        self._bw = bw
        self._server_url = server_url
        self._pw = open(master_password_file).read().strip()
        self._session = None

    def _run(self, *args, env_extra=None):
        env = dict(os.environ, **(env_extra or {}))
        p = subprocess.run([self._bw, *args], env=env, capture_output=True, text=True, timeout=30)
        if p.returncode != 0:
            raise BackendError(f"bw {args[0]} failed: {p.stderr.strip()[:200]}")
        return p.stdout.strip()

    def _unlock(self):
        self._run("config", "server", self._server_url)
        status = json.loads(self._run("status"))["status"]
        if status == "unauthenticated":
            self._run("login", "--apikey")
        self._session = self._run("unlock", "--passwordenv", "BW_MASTER_PW", "--raw",
                                  env_extra={"BW_MASTER_PW": self._pw})

    def get(self, item, field):
        if self._session is None:
            self._unlock()
        self._run("sync", "--session", self._session)
        raw = self._run("get", "item", item, "--session", self._session)
        obj = json.loads(raw)
        if field == "password" and obj.get("login"):
            return obj["login"]["password"]
        if field == "username" and obj.get("login"):
            return obj["login"]["username"]
        if field == "notes":
            return obj.get("notes") or ""
        for f in obj.get("fields") or []:
            if f.get("name") == field:
                return f.get("value") or ""
        raise BackendError(f"field {field!r} not found on item {item!r}")

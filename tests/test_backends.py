"""Runs the backend conformance suite (tests/backend_contract.py) against every
bundled backend: MemoryBackend, FileBackend, LocalBackend (file and env key
sources), and BwBackend / BwServeBackend against the fake `bw` of test_e2e."""
import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from backend_contract import BackendContract  # noqa: E402
from secret_broker.backends import (BwBackend, BwServeBackend, FileBackend, Item, LocalBackend,  # noqa: E402
                                    MemoryBackend)
from secret_broker.backends import localstore as ls  # noqa: E402
from test_e2e import FAKE_BW  # noqa: E402


def _variant(name):
    """A name that differs from `name` only by case."""
    return name.lower() if name != name.lower() else name.upper()


class MemoryContract(BackendContract, unittest.TestCase):
    def make(self, **kw):
        return MemoryBackend()

    def seed(self, backend, kind, name):
        if kind != "duplicate":
            return False
        backend._items[_variant(name)] = Item(_variant(name), "note", notes="dupe")
        return True


class FileContract(BackendContract, unittest.TestCase):
    def make(self, **kw):
        path = os.path.join(tempfile.mkdtemp(), "vault.json")
        with open(path, "w") as f:
            f.write("{}")
        return FileBackend(path)

    def seed(self, backend, kind, name):
        if kind != "duplicate":
            return False
        backend._data[_variant(name)] = {"notes": "dupe"}
        return True


class LocalFileKeyContract(BackendContract, unittest.TestCase):
    """Passphrase in a key file (scrypt)."""
    persistent = True
    supports_idle = True
    PASS = "correct horse battery staple (fake)"

    def make(self, idle_timeout=None, **kw):
        d = tempfile.mkdtemp()
        self.path = os.path.join(d, "store.enc")
        self.keyfile = os.path.join(d, "key")
        with open(self.keyfile, "w") as f:
            f.write(self.PASS + "\n")
        os.chmod(self.keyfile, 0o600)
        ls.create_store(self.path, ls.Key(self.PASS))
        self.idle = 300 if idle_timeout is None else idle_timeout
        return LocalBackend(self.path, ls.FileKeySource(self.keyfile), self.idle)

    def reopen(self, backend):
        return LocalBackend(self.path, ls.FileKeySource(self.keyfile), self.idle)

    def seed(self, backend, kind, name):
        if kind != "duplicate":
            return False
        backend._store.mutate(lambda items: items.__setitem__(
            _variant(name), {"type": "note", "notes": "dupe", "uris": [], "fields": {}}))
        return True


class LocalEnvKeyContract(LocalFileKeyContract):
    """Raw 32-byte key from an environment variable (no KDF)."""
    RAW = base64.b64encode(bytes(range(32))).decode()

    def make(self, idle_timeout=None, **kw):
        os.environ["ASB_CONTRACT_KEY"] = self.RAW
        self.addCleanup(os.environ.pop, "ASB_CONTRACT_KEY", None)
        d = tempfile.mkdtemp()
        self.path = os.path.join(d, "store.enc")
        ls.create_store(self.path, ls.Key(self.RAW))
        self.idle = 300 if idle_timeout is None else idle_timeout
        return LocalBackend(self.path, ls.EnvKeySource("ASB_CONTRACT_KEY"), self.idle)

    def reopen(self, backend):
        return LocalBackend(self.path, ls.EnvKeySource("ASB_CONTRACT_KEY"), self.idle)


class BwContract(BackendContract, unittest.TestCase):
    """BwBackend against the fake `bw` executable (no network, no real vault)."""
    backend_class = BwBackend
    persistent = True
    supports_idle = True
    ci_lookup = False               # the CLI's `bw get item NAME` is not an exact, case-folded match

    def make(self, idle_timeout=None, **kw):
        d = tempfile.mkdtemp()
        self.state = os.path.join(d, "state.json")
        self.bw = os.path.join(d, "bw")
        with open(self.bw, "w") as f:
            f.write(FAKE_BW)
        os.chmod(self.bw, 0o755)
        os.environ["FAKE_BW_STATE"] = self.state
        self.addCleanup(os.environ.pop, "FAKE_BW_STATE", None)
        self.pw = os.path.join(d, "pw")
        with open(self.pw, "w") as f:
            f.write("m")
        self.idle = 0 if idle_timeout is None else idle_timeout
        return self._new()

    def _new(self):
        return self.backend_class("https://v.example", self.pw, bw=self.bw, idle_timeout=self.idle,
                                  organization="Org", collection="Shared")

    def reopen(self, backend):
        return self._new()

    def seed(self, backend, kind, name):
        data = {"items": [], "in": False, "n": 0}
        if os.path.exists(self.state):
            with open(self.state) as f:
                data = json.load(f)
        data["n"] += 1
        base = {"id": f"seed{data['n']}", "organizationId": "org1", "collectionIds": ["col1"]}
        if kind == "card":
            data["items"].append({**base, "name": name, "type": 3, "card": {"number": "4111"}})
        elif kind == "identity":
            data["items"].append({**base, "name": name, "type": 4, "identity": {"firstName": "A"}})
        elif kind == "duplicate":
            data["items"].append({**base, "name": _variant(name), "type": 2, "notes": "dupe",
                                  "secureNote": {"type": 0}})
        else:
            return False
        with open(self.state, "w") as f:
            json.dump(data, f)
        return True


class BwServeContract(BwContract):
    """The same, through one long-lived `bw serve`."""
    backend_class = BwServeBackend
    ci_lookup = True


if __name__ == "__main__":
    unittest.main()

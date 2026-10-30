"""A change made in the vault's own client (a Bitwarden app) reaches the broker promptly: a request that names a
credential the catalog does not have first pulls the latest from a remote vault (rate limited), instead of
waiting for the next periodic sync. Requests for known names do not trigger a sync.
"""
import _fast  # noqa: F401
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()


class Sync(t.Harness):
    def setUp(self):
        super().setUp()
        self.syncs = []
        self.broker.backend.sync = lambda min_age=0: self.syncs.append(min_age)

    def add_in_vault(self, item, name):
        self.broker.backend._data[item] = {"token": "x", "broker": json.dumps(
            {"name": name, "vars": {name.upper() + "_TOKEN": {"item": item, "field": "token"}},
             "allowed_hosts": ["127.0.0.1"]})}

    def test_an_unknown_name_syncs_then_finds_the_new_credential(self):
        self.broker.refresh_catalog()                      # the catalog is fresh: only a miss re-reads
        self.add_in_vault("Late", "late")
        code, _ = self.create_env(("late",))
        self.assertEqual(code, 202)
        self.assertEqual(self.syncs, [self.broker.FORCED_SYNC_MIN_AGE])

    def test_a_known_name_does_not_sync(self):
        self.broker.refresh_catalog()
        self.create_env(("svc",))
        self.assertEqual(self.syncs, [])

    def test_still_unknown_after_the_sync_is_refused(self):
        code, _ = self.create_env(("nope",))
        self.assertEqual(code, 400)
        self.assertEqual(self.syncs, [self.broker.FORCED_SYNC_MIN_AGE])


class Config(unittest.TestCase):
    def test_sync_interval_is_validated_and_used(self):
        from secret_broker.backends import bitwarden as bw
        from secret_broker.backends.base import BackendConfigError
        pw = os.path.join(tempfile.mkdtemp(), "pw")
        open(pw, "w").write("m")
        base = {"server_url": "https://v.example", "master_password_file": pw}
        bw.validate({**base, "sync_interval": 15})
        for bad in (-1, "60", True):
            with self.assertRaises(BackendConfigError):
                bw.validate({**base, "sync_interval": bad})
        self.assertEqual(bw.build({**base, "sync_interval": 15})._sync_interval, 15)
        self.assertEqual(bw.build(base)._sync_interval, 60)


if __name__ == "__main__":
    unittest.main()

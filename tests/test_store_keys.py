"""`asb store NAME --hosts H --keys`: one credential with several variables, from KEY=value lines or a JSON object
on stdin (issue #47). The note is stored as given, each key becomes a variable of the same name mapped with
`key`, and the usual store policy applies. No value appears in an error, the card or the audit log.
"""
import _fast  # noqa: F401
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
from secret_broker import structured  # noqa: E402
CLI = os.environ.get("ASB_CLI") or os.path.join(os.path.dirname(__file__), "..", "client", "asb")

V1, V2, V3 = "S3CR3T-keys-a1", "S3CR3T-keys-b2", "S3CR3T-keys-c3"
LINES = f"API_TOKEN={V1}\nCF_CLIENT_ID={V2}\n# a comment\nCF_CLIENT_SECRET={V3}\n"


class Base(t.Harness):
    def create(self, value, name="cfapi", expect=202, **extra):
        body = {"mode": "store", "names": [name], "op": "create", "value": value,
                "allowed_hosts": ["api.example.com"], "keys": True, **extra}
        code, out = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, expect, out)
        return json.loads(out)

    def settle(self, rid):
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        return json.loads(b)


class Create(Base):
    def test_key_value_lines_become_one_credential_with_three_variables(self):
        r = self.settle(self.create(LINES)["id"])
        self.assertEqual(r["status"], "approved", r)
        sc = self.broker.cfg["secrets"]["cfapi"]
        self.assertEqual(sc["vars"], {k: {"item": "cfapi", "field": "notes", "key": k}
                                      for k in ("API_TOKEN", "CF_CLIENT_ID", "CF_CLIENT_SECRET")})
        stored = self.broker.backend.get("cfapi", "notes")
        self.assertEqual(stored, LINES)                                   # the note as given, comment included
        self.assertEqual(structured.get(stored, "CF_CLIENT_ID"), V2)
        self.assertEqual(self.disk()["secrets"]["cfapi"]["vars"]["CF_CLIENT_SECRET"],
                         {"field": "notes", "key": "CF_CLIENT_SECRET"})
        ev = self.events("stored")[-1]
        self.assertEqual(ev["var_names"], ["API_TOKEN", "CF_CLIENT_ID", "CF_CLIENT_SECRET"])
        audit = open(self.audit).read()
        for v in (V1, V2, V3):
            self.assertNotIn(v, audit)

    def test_a_json_object(self):
        text = json.dumps({"API_TOKEN": V1, "CF_CLIENT_ID": V2})
        self.settle(self.create(text)["id"])
        sc = self.broker.cfg["secrets"]["cfapi"]
        self.assertEqual(sorted(sc["vars"]), ["API_TOKEN", "CF_CLIENT_ID"])
        self.assertEqual(structured.get(self.broker.backend.get("cfapi", "notes"), "API_TOKEN"), V1)


    def test_one_key_can_then_be_updated_alone(self):
        self.settle(self.create(LINES)["id"])
        code, out = self.api("POST", "/v1/requests", {"mode": "store", "names": ["cfapi"], "op": "update",
                                                       "var": "CF_CLIENT_ID", "value": "S3CR3T-keys-new"})
        self.assertEqual(code, 202, out)
        rid = json.loads(out)["id"]
        self.assertEqual(self.settle(rid)["status"], "approved")
        stored = self.broker.backend.get("cfapi", "notes")
        self.assertEqual(structured.get(stored, "CF_CLIENT_ID"), "S3CR3T-keys-new")
        self.assertEqual(structured.get(stored, "API_TOKEN"), V1)


class Card(Base):
    def tweak(self, cfg):
        cfg["store"] = {"create": "prompt"}         # so the create is shown to the human

    def test_the_card_names_the_variables_not_the_values(self):
        r = self.create(LINES)
        self.settle(r["id"])
        n = self.notifier.notifications[-1]
        self.assertIn("variables API_TOKEN, CF_CLIENT_ID, CF_CLIENT_SECRET", n.text)
        flat = json.dumps([x.text for x in self.notifier.notifications])
        for v in (V1, V2, V3):
            self.assertNotIn(v, flat)


class Refused(Base):
    def test_refusals_name_no_value(self):
        cases = {
            "with keys, the value must be a JSON object or KEY=value lines": "S3CR3T-keys-plain-token",
            "with keys, the value needs 2 to 20 keys": f"ONLY={V1}",
            "with keys, a key appears twice: DUP": f"DUP={V1}\nDUP={V2}\n",
            "with keys, a key appears twice: A": '{"A": "%s", "A": "%s", "B": "x"}' % (V1, V2),
            "with keys, each key must look like MY_TOKEN: cf-id": f"cf-id={V1}\nOTHER={V2}\n",
            "with keys, each key must look like MY_TOKEN: PATH": f"PATH={V1}\nOTHER={V2}\n",
            "with keys, a key has an empty value: EMPTY": f"EMPTY=\nOTHER={V2}\n",
            "with keys, each value must be text: B": json.dumps({"A": V1, "B": 5}),
        }
        cases["with keys, each key must look like MY_TOKEN: (not a plain name)"] = json.dumps(
            {"S3CR3T-keys-as-a-key x": V1, "B": V2})                     # a key that is not a name is not repeated
        many = "".join(f"K{i}=S3CR3T-v{i}\n" for i in range(21))
        cases["with keys, the value needs 2 to 20 keys"] = many
        for msg, value in cases.items():
            with self.subTest(msg):
                code, out = self.api("POST", "/v1/requests", {"mode": "store", "names": ["cfapi"], "op": "create",
                                                               "value": value, "allowed_hosts": ["api.example.com"],
                                                               "keys": True})
                self.assertEqual(code, 400, out)
                self.assertIn(msg, out)
                for v in (V1, V2, "S3CR3T-keys-plain-token", "S3CR3T-v1", "S3CR3T-keys-as-a-key"):
                    self.assertNotIn(v, out)
        self.assertNotIn("cfapi", self.broker.cfg["secrets"])
        self.assertEqual(self.events("requested"), [])                    # refused before a request existed
        audit = open(self.audit).read()
        self.assertTrue(self.records())                                    # the log is there (catalog_loaded)
        for v in (V1, V2, "S3CR3T-keys-plain-token"):
            self.assertNotIn(v, audit)

    def test_keys_does_not_combine(self):
        for extra, msg in (({"var": "X_TOKEN"}, "keys names the variables itself; leave out var"),
                           ({"ssh": True}, "keys does not apply to an ssh key")):
            with self.subTest(msg):
                code, out = self.api("POST", "/v1/requests", {"mode": "store", "names": ["cfapi"], "op": "create",
                                                               "value": LINES, "allowed_hosts": ["api.example.com"],
                                                               "keys": True, **extra})
                self.assertEqual(code, 400, out)
                self.assertIn(msg, out)
        code, out = self.api("POST", "/v1/requests", {"mode": "store", "names": ["svc"], "op": "update",
                                                       "value": LINES, "keys": True})
        self.assertEqual(code, 400, out)
        self.assertIn("keys applies when creating a credential", out)


class Cli(Base):
    def run_cli(self, *args, stdin=LINES):
        env = {"PATH": os.environ["PATH"], "HOME": self.tmp, "SECRET_BROKER_URL": self.base,
               "SECRET_BROKER_KEY": t.KEY}
        return subprocess.run([CLI, *args], env=env, capture_output=True, text=True, timeout=60, input=stdin)

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()

    def test_store_with_keys(self):
        r = self.run_cli("store", "cfapi", "--hosts", "api.example.com", "--keys")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "stored: cfapi (create) -> item 'cfapi' field notes")
        self.assertIn("variables: API_TOKEN, CF_CLIENT_ID, CF_CLIENT_SECRET", r.stderr)
        self.assertEqual(sorted(self.broker.cfg["secrets"]["cfapi"]["vars"]),
                         ["API_TOKEN", "CF_CLIENT_ID", "CF_CLIENT_SECRET"])
        for v in (V1, V2, V3):
            self.assertNotIn(v, r.stdout + r.stderr)

    def test_usage_errors(self):
        for args in (("store", "cfapi", "--hosts", "api.example.com", "--keys", "--var", "X_TOKEN"),
                     ("store", "cfapi", "--hosts", "api.example.com", "--keys", "--ssh"),
                     ("update", "svc", "--keys")):
            with self.subTest(args):
                r = self.run_cli(*args)
                self.assertEqual(r.returncode, 2, r.stderr)
        self.assertNotIn("cfapi", self.broker.cfg["secrets"])
        self.assertEqual(self.events("requested"), [])


if __name__ == "__main__":
    unittest.main()

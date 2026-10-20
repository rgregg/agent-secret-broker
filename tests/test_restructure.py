import unittest

from secret_broker import restructure


class Fake:
    capabilities = frozenset({"create_login", "edit_item", "set_meta"})

    def __init__(self, items, corrupt=False):
        self.items, self.corrupt = items, corrupt     # name -> {"notes","meta"} | login dict

    def catalog(self):
        return [{"item": n, "meta": i.get("meta")} for n, i in self.items.items() if i.get("meta")]

    def get(self, item, field):
        v = self.items[item][field]
        return v + "x" if self.corrupt and item.endswith("(login)") else v

    def create_login(self, item, username, password, uri=None, notes=None, meta=None):
        self.items[item] = {"username": username, "password": password, "uri": uri, "notes": notes}

    def put(self, item, field, value, create=False, meta=None, **kw):
        self.items[item] = {field: value, "meta": meta}

    def delete(self, item):
        del self.items[item]

    def edit_item(self, item, new_name=None, meta=None, drop_meta=False):
        obj = self.items.pop(item)
        if meta is not None:
            obj["meta"] = meta
        self.items[new_name or item] = obj


NOTE = "email: a@b.example\npassword: pw1\nurl: https://x.example\nhost: h\nnotes: n"
LOGIN = {"secret": "npm", "kind": "login", "username": "email", "password": "password",
         "uri": "url", "notes": ["host", "notes"],
         "vars": {"NPM_EMAIL": {"field": "username"}, "NPM_PASSWORD": {"field": "password"}}}


class Restructure(unittest.TestCase):
    def meta(self):
        return {"name": "npm", "allowed_hosts": ["h.example"], "approval": "prompt",
                "vars": {"OLD": {"key": "password"}}}

    def test_login_replaces_the_note_after_verification(self):
        f = Fake({"npm": {"notes": NOTE, "meta": self.meta()}})
        self.assertEqual(restructure.run(f, [LOGIN], apply=True, pause=0, out=lambda *_: None), 0)
        self.assertEqual(list(f.items), ["npm"])
        it = f.items["npm"]
        self.assertEqual((it["username"], it["password"], it["uri"]),
                         ("a@b.example", "pw1", "https://x.example"))
        self.assertEqual(it["meta"]["vars"], LOGIN["vars"])
        self.assertEqual(it["meta"]["allowed_hosts"], ["h.example"])

    def test_old_item_survives_a_mismatch(self):
        f = Fake({"npm": {"notes": NOTE, "meta": self.meta()}}, corrupt=True)
        self.assertEqual(restructure.run(f, [LOGIN], apply=True, pause=0, out=lambda *_: None), 1)
        self.assertIn("npm", f.items)
        self.assertEqual(f.items["npm"]["notes"], NOTE)

    def test_dry_run_changes_nothing_and_missing_keys_fail(self):
        f = Fake({"npm": {"notes": "email: a\npassword: b", "meta": self.meta()}})
        self.assertEqual(restructure.run(f, [LOGIN], apply=False, pause=0, out=lambda *_: None), 1)
        self.assertEqual(list(f.items), ["npm"])

    def test_split_creates_one_item_per_value(self):
        f = Fake({"npm": {"notes": "a-key: 1\nb-key: 2", "meta": self.meta()}})
        plan = [{"secret": "npm", "kind": "split", "into": [
            {"name": "s-a", "key": "a-key", "var": "A"}, {"name": "s-b", "key": "b-key", "var": "B"}]}]
        self.assertEqual(restructure.run(f, plan, apply=True, pause=0, out=lambda *_: None), 0)
        self.assertEqual(sorted(f.items), ["s-a", "s-b"])
        self.assertEqual(f.items["s-b"]["meta"]["vars"], {"B": {"field": "password"}})
        self.assertEqual(f.items["s-b"]["meta"]["name"], "s-b")


if __name__ == "__main__":
    unittest.main()

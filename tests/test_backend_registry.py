import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import proposals  # noqa: E402
from secret_broker.__main__ import build_backend  # noqa: E402
from secret_broker.backends import (BackendConfigError, BackendConflict, BackendError,  # noqa: E402
                                    BackendInvalid, BackendNotFound, BackendRateLimited,
                                    BackendSpec, BackendUnavailable, BwBackend, BwServeBackend,
                                    MemoryBackend, NotSupported, VaultBackend, error_class,
                                    registry)

ROOT = os.path.join(os.path.dirname(__file__), "..", "secret_broker")


class Registry(unittest.TestCase):
    def setUp(self):
        self.added = []

    def tearDown(self):
        for n in self.added:
            registry._specs.pop(n, None)

    def reg(self, spec, **kw):
        registry.register(spec, **kw)
        self.added.append(spec.name)

    def test_bundled_types(self):
        self.assertEqual(registry.known(), ["bw", "file", "local", "memory"])

    def test_unknown_type_names_the_field_and_lists_types(self):
        with self.assertRaises(BackendConfigError) as cm:
            build_backend({"backend": {"type": "nope"}})
        msg = str(cm.exception)
        self.assertIn("backend.type", msg)
        for t in ("bw", "local", "file"):
            self.assertIn(t, msg)

    def test_missing_or_malformed_backend_block(self):
        for cfg in ({}, {"backend": "bw"}, {"backend": {}}, {"backend": {"type": 5}}):
            with self.assertRaises(BackendConfigError) as cm:
                build_backend(cfg)
            self.assertIn("backend", str(cm.exception))

    def test_bw_validation_names_the_field(self):
        pw = os.path.join(tempfile.mkdtemp(), "pw")
        open(pw, "w").write("x")
        good = {"type": "bw", "server_url": "https://v.example", "master_password_file": pw}
        self.assertIs(type(build_backend({"backend": good})), BwBackend)
        self.assertIs(type(build_backend({"backend": {**good, "serve": True}})), BwServeBackend)
        for patch, field in (({"server_url": None}, "server_url"), ({"master_password_file": ""},
                             "master_password_file"), ({"idle_timeout": -1}, "idle_timeout"),
                             ({"serve": "yes"}, "serve"), ({"prewarm": 1}, "prewarm"),
                             ({"organization": 3}, "organization")):
            with self.assertRaises(BackendConfigError) as cm:
                build_backend({"backend": {**good, **patch}})
            self.assertIn(f"backend.{field}", str(cm.exception))

    def test_bw_ignores_unknown_keys_as_before(self):
        pw = os.path.join(tempfile.mkdtemp(), "pw")
        open(pw, "w").write("x")
        b = build_backend({"backend": {"type": "bw", "server_url": "u", "master_password_file": pw,
                                       "something_old": 1}})
        self.assertIsInstance(b, BwBackend)

    def test_prewarm_false_removes_the_warm_capability(self):
        pw = os.path.join(tempfile.mkdtemp(), "pw")
        open(pw, "w").write("x")
        cfg = {"type": "bw", "server_url": "u", "master_password_file": pw}
        self.assertIn("warm", build_backend({"backend": cfg}).capabilities)
        self.assertNotIn("warm", build_backend({"backend": {**cfg, "prewarm": False}}).capabilities)

    def test_bw_adopts_only_when_scoped(self):
        pw = os.path.join(tempfile.mkdtemp(), "pw")
        open(pw, "w").write("x")
        cfg = {"type": "bw", "server_url": "u", "master_password_file": pw}
        self.assertNotIn("adopts", build_backend({"backend": cfg}).capabilities)
        both = build_backend({"backend": {**cfg, "organization": "O", "collection": "C"}})
        self.assertIn("adopts", both.capabilities)

    def test_register_a_third_party_backend(self):
        built = []

        def build(b):
            built.append(b)
            return MemoryBackend()
        self.reg(BackendSpec("mine", build, lambda b: None, "mine"))
        b = build_backend({"backend": {"type": "mine", "x": 1}})
        self.assertIsInstance(b, MemoryBackend)
        self.assertEqual(built, [{"type": "mine", "x": 1}])

    def test_validate_runs_before_build(self):
        def bad(b):
            raise BackendConfigError("backend.url: required")
        self.reg(BackendSpec("v", lambda b: self.fail("built"), bad))
        with self.assertRaises(BackendConfigError):
            build_backend({"backend": {"type": "v"}})

    def test_cannot_shadow_a_name_without_replace(self):
        with self.assertRaises(ValueError):
            registry.register(BackendSpec("bw", lambda b: None, lambda b: None))
        with self.assertRaises(TypeError):
            registry.register("not a spec")

    def test_entry_point_plugins_load_and_failures_are_not_fatal(self):
        class EP:
            def __init__(self, name, obj=None, exc=None):
                self.name, self._obj, self._exc = name, obj, exc

            def load(self):
                if self._exc:
                    raise self._exc
                return self._obj
        good = BackendSpec("plug-a", lambda b: MemoryBackend(), lambda b: None)
        eps = [EP("a", good),
               EP("b", exc=ImportError("no module named secret-thing")),
               EP("c", obj=lambda: BackendSpec("plug-c", lambda b: MemoryBackend(), lambda b: None)),
               EP("d", obj=lambda: 1 / 0),
               EP("e", obj=BackendSpec("bw", lambda b: None, lambda b: None))]     # clashes
        self.added += ["plug-a", "plug-c"]
        with self.assertLogs("secret_broker.backends", "WARNING") as cm:
            loaded = registry.load_plugins(eps)
        self.assertEqual(loaded, ["plug-a", "plug-c"])
        self.assertEqual(len([m for m in cm.output if "not loaded" in m]), 3)
        self.assertIn("plug-a", registry.known())

    def test_local_validation_goes_through_the_registry(self):
        for b, field in (({"type": "local"}, "backend.path"),
                         ({"type": "local", "path": "/x"}, "backend.key_source"),
                         ({"type": "local", "path": "/x", "key_source": {"type": "file"}},
                          "backend.key_source.path"),
                         ({"type": "local", "path": "/x", "key_source": {"type": "env", "name": "N"},
                           "bogus": 1}, "backend.bogus")):
            with self.assertRaises(BackendConfigError) as cm:
                build_backend({"backend": b})
            self.assertIn(field, str(cm.exception))


class ErrorClasses(unittest.TestCase):
    def test_typed_errors_decide_by_class_not_text(self):
        self.assertEqual(error_class(BackendRateLimited("x")), "rate_limited")
        self.assertEqual(error_class(BackendUnavailable("x")), "backend_unavailable")
        self.assertEqual(error_class(BackendConflict("x")), "conflict")
        for e in (BackendNotFound("x"), BackendInvalid("x"), NotSupported("x")):
            self.assertEqual(error_class(e), "invalid")
        # the text of a typed error is ignored
        self.assertEqual(error_class(BackendConflict("not found, 503, timed out")), "conflict")
        self.assertEqual(error_class(BackendNotFound("429 too many requests")), "invalid")

    def test_plain_errors_fall_back_to_text(self):
        for text, cls in (("429 Too Many Requests", "rate_limited"), ("connection refused", "backend_unavailable"),
                          ("409 conflict", "conflict"), ("item not found", "invalid"),
                          ("something odd", "other")):
            self.assertEqual(error_class(BackendError(text)), cls)
        self.assertEqual(error_class(TimeoutError()), "backend_unavailable")
        self.assertEqual(error_class(KeyError("k")), "invalid")

    def test_every_error_class_is_a_backend_error(self):
        for c in (BackendRateLimited, BackendUnavailable, BackendConflict, BackendNotFound,
                  BackendInvalid, NotSupported):
            self.assertTrue(issubclass(c, BackendError))

    def test_guidance_apply_classifier_uses_the_typed_class_first(self):
        self.assertEqual(proposals.classify(BackendRateLimited("boom")), "rate_limited")
        self.assertEqual(proposals.classify(BackendUnavailable("boom")), "backend_unavailable")
        self.assertEqual(proposals.classify(BackendConflict("boom")), "conflict")
        self.assertEqual(proposals.classify(BackendError("503 bad gateway")), "backend_unavailable")
        self.assertEqual(proposals.classify(ValueError("x")), "invalid")
        self.assertEqual(proposals.classify(BackendError("who knows")), "other")
        self.assertTrue(proposals.TRANSIENT >= {"rate_limited", "backend_unavailable", "conflict"})

    def test_bitwarden_messages_are_classified(self):
        from secret_broker.backends.bitwarden import _bw_error
        self.assertIsInstance(_bw_error("bw sync failed: Too many requests"), BackendRateLimited)
        self.assertIsInstance(_bw_error("bw get failed: Not found."), BackendNotFound)
        self.assertIsInstance(_bw_error("bw get failed: connection refused"), BackendUnavailable)
        self.assertIsInstance(_bw_error("bw edit failed: 409 conflict"), BackendConflict)
        self.assertIsInstance(_bw_error("bw ? failed: no rights"), BackendInvalid)
        self.assertIs(type(_bw_error("bw ? failed: huh")), BackendError)


class CapabilityDefaults(unittest.TestCase):
    def test_base_defaults(self):
        class Min(VaultBackend):
            def get(self, item, field): return ""
            def put(self, *a, **k): pass
            def catalog(self): return []
            def set_meta(self, item, meta): pass
            def delete(self, item): pass
        m = Min()
        self.assertEqual(m.capabilities, frozenset())
        for call in (lambda: m.create_login("a", "u", "p"), lambda: m.edit_item("a"), m.warm,
                     m.export_items, lambda: m.import_items([])):
            with self.assertRaises(NotSupported):
                call()
        m.close()
        m.close()
        self.assertIsNone(m.on_event)
        seen = []
        m.on_event = lambda n, **f: seen.append(n)
        m._emit("x")
        m.on_event = lambda n, **f: 1 / 0
        m._emit("x")                      # a failing hook never raises
        self.assertEqual(seen, ["x"])

    def test_abstract_methods_are_enforced(self):
        class Bad(VaultBackend):
            def get(self, item, field): return ""
        with self.assertRaises(TypeError):
            Bad()


class CoreIsBackendNeutral(unittest.TestCase):
    """The broker core depends on the contract only (guards against re-introducing leaks)."""
    CORE = [f for f in os.listdir(ROOT) if f.endswith(".py")]

    def source(self, name):
        with open(os.path.join(ROOT, name)) as f:
            return f.read()

    def test_no_attribute_probing_of_the_backend(self):
        pat = re.compile(r"(hasattr|getattr)\(\s*(self\.)?backend\b")
        for name in self.CORE:
            self.assertIsNone(pat.search(self.source(name)), name)

    def test_core_never_imports_a_concrete_backend(self):
        allowed = {"__main__.py", "localstore.py", "localstore_cli.py"}
        pat = re.compile(r"from \.backends\.(bitwarden|local|localstore|file|memory)|"
                         r"from \.backends import .*(Bw|Local|File|Memory)")
        for name in self.CORE:
            if name not in allowed:
                self.assertIsNone(pat.search(self.source(name)), name)

    def test_no_vault_product_words_in_core_code(self):
        words = re.compile(r"bitwarden|vaultwarden|organizationId|collectionIds|prewarm|bw serve",
                           re.IGNORECASE)
        for name in self.CORE:
            if name in ("localstore_cli.py", "localstore.py"):
                continue
            code = "\n".join(line.split("#", 1)[0] for line in self.source(name).splitlines())
            self.assertIsNone(words.search(code), name)

    def test_no_product_specific_backend_config_keys_in_core(self):
        for name in self.CORE:
            if name in ("localstore_cli.py",):
                continue
            src = self.source(name)
            for key in ('"organization"', '"collection"', '"serve"', '"server_url"',
                        '"master_password_file"'):
                self.assertNotIn(key, src, f"{name}: {key}")


if __name__ == "__main__":
    unittest.main()

"""Security regression: a credential value must never come back out of an error path.

Report 1: http.client quotes the filled-in header value or path in its exception text, and the
broker used to put `str(e)` into the agent's answer, the audit log and the history. Every case
here injects a credential value that breaks the filled request in a different way (CRLF, a space
in the path, a non-ASCII character, the value used as the port) and asserts that the secret
string appears NOWHERE the agent, a log, a page or a notification could see it.

Every secret here is fake; every server is a loopback stub or an in-process broker.
"""
import contextlib
import http.client
import io
import json
import logging
import os
import socket
import sys
import traceback
import unittest
import urllib.error
import urllib.parse
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
try:
    from secret_broker import destguard as _destguard  # noqa: E402
    _destguard.allow_loopback_for_tests()
except ImportError:         # the pre-fix tree has no guard: the leak tests must still run (and fail) there
    pass
import test_e2e as t  # noqa: E402
import test_sessions as ts  # noqa: E402
import plan_base as pb  # noqa: E402
import test_ssh_rules as tr  # noqa: E402
import test_grants as tg  # noqa: E402

CORE = "S3CRET-core-9f3a77"
BAD_VALUES = {
    "crlf": CORE + "\r\nX-Injected: y",
    "nonascii": CORE + "☃é",
    "tab-nul": CORE + "\x00\x01",
}
SPACE = CORE + " tail"      # legal in a header value, illegal in a path or query


class Everywhere:
    """Collects every place a value could surface, then asserts the secret is in none of them."""

    def _capture(self):
        self._buf = io.StringIO()
        self._log_handler = logging.StreamHandler(self._buf)
        logging.getLogger().addHandler(self._log_handler)
        logging.getLogger().setLevel(logging.DEBUG)
        self.addCleanup(logging.getLogger().removeHandler, self._log_handler)
        self._stack = contextlib.ExitStack()
        self._stack.enter_context(contextlib.redirect_stdout(self._buf))
        self._stack.enter_context(contextlib.redirect_stderr(self._buf))
        self.addCleanup(self._stack.close)

    def surfaces(self):
        out = {"stdout/stderr/logging": self._buf.getvalue(),
               "audit file": open(self.audit).read(),
               "notifications": json.dumps([[n.get("title"), n.get("text"), n.get("url")]
                                            if isinstance(n, dict) else repr(n)
                                            for n in getattr(self.notifier, "sent", [])], default=str),
               "agent responses": "\n".join(getattr(self, "seen_bodies", []))}
        d = os.path.dirname(self.audit)
        for f in os.listdir(d):
            if f not in ("audit.jsonl", "vault.json"):
                with open(os.path.join(d, f), "rb") as fh:
                    out["file:" + f] = fh.read().decode("latin-1")
        h = self.broker.history
        rows = h.rows((), None, None, None, None)
        out["history rows"] = json.dumps(rows, default=str)
        for r in rows:
            row, evs = h.detail(r["id"])
            out["history detail " + r["id"]] = json.dumps([row, evs], default=str)
            if self.broker.details is not None and hasattr(self.broker.details, "get"):
                out["request details " + r["id"]] = json.dumps(self.broker.details.get(r["id"]), default=str)
            for req in list(self.broker._by_id.values()):
                out["request object " + req.id] = json.dumps(
                    {"status": req.status, "error": req.error, "names": req.names}, default=str)
        return out

    def assert_no_leak(self, secret=CORE, extra=None):
        pages = {}
        try:
            for path in ("/", "/history", "/?view=all"):
                pages["page " + path] = self.get(path)[1]
        except Exception:      # noqa: BLE001 -- pages are best effort; the other surfaces are the point
            pass
        for where, text in {**self.surfaces(), **pages, **(extra or {})}.items():
            self.assertNotIn(secret, text, f"secret leaked into {where}")
            self.assertNotIn(secret.encode().hex(), text, f"secret (hex) leaked into {where}")


class HttpBase(Everywhere, t.Harness):
    value = CORE
    decision = "approve"

    def tweak(self, cfg):
        cfg.setdefault("_vault", {})["Svc"] = {"token": self.value}
        cfg["request_details"] = {"enabled": True}
        self.tweak2(cfg)

    def tweak2(self, cfg):
        pass

    def setUp(self):
        super().setUp()
        self._capture()
        self.seen_bodies = []
        self.port = self.up.server_address[1]

    def tearDown(self):
        self._stack.close()
        super().tearDown()

    def go(self, url=None, headers=None, wait=5, **kw):
        body = {"mode": "http", "names": ["svc"], "method": "GET",
                "url": url or f"http://127.0.0.1:{self.port}/x",
                "headers": headers if headers is not None else {"Authorization": "Bearer {{SVC_TOKEN}}"}, **kw}
        code, text = self.api("POST", "/v1/requests", body)
        self.seen_bodies.append(text)
        if code != 202:
            return code, json.loads(text), None
        rid = json.loads(text)["id"]
        c2, t2 = self.api("GET", f"/v1/requests/{rid}?wait={wait}")
        self.seen_bodies.append(t2)
        return c2, json.loads(t2), rid

    def get(self, path):
        import urllib.request
        r = urllib.request.Request(self.abase + path, headers={"X-authentik-username": self.user})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()


class FilledValueBreaksRequest(HttpBase):
    """The credential VALUE is hostile; the agent's template is innocent."""

    def run_case(self, value, url=None, headers=None):
        self.broker.backend._data["Svc"]["token"] = value
        t.Echo.hits.clear()
        code, got, rid = self.go(url, headers)
        self.assertEqual(code, 200, got)
        self.assertEqual(got["status"], "failed", got)
        self.assertEqual(got["error"], "release failed: invalid request")
        self.assertEqual(t.Echo.hits, [], "nothing may reach the upstream")
        self.assertEqual(self.events("failed")[-1]["error"], "release failed: invalid request")
        self.assert_no_leak()
        return rid

    def test_crlf_in_header_value(self):
        self.run_case(BAD_VALUES["crlf"])

    def test_control_chars_in_header_value(self):
        self.run_case(BAD_VALUES["tab-nul"])

    def test_non_ascii_in_header_value(self):
        self.run_case(BAD_VALUES["nonascii"])

    def test_space_in_path(self):
        self.run_case(SPACE, url="http://127.0.0.1:%d/x/{{SVC_TOKEN}}" % self.port, headers={})

    def test_crlf_in_path(self):
        self.run_case(BAD_VALUES["crlf"], url="http://127.0.0.1:%d/x/{{SVC_TOKEN}}" % self.port, headers={})

    def test_non_ascii_in_path(self):
        self.run_case(BAD_VALUES["nonascii"], url="http://127.0.0.1:%d/x/{{SVC_TOKEN}}" % self.port, headers={})

    def test_space_in_query(self):
        self.run_case(SPACE, url="http://127.0.0.1:%d/x?k={{SVC_TOKEN}}" % self.port, headers={})

    def test_value_that_rewrites_the_host_via_the_path_start(self):
        # `@evil` in the first path segment is harmless, but a value that closes the authority is not
        self.broker.backend._data["Svc"]["token"] = "1@evil.example"
        code, got, rid = self.go("http://127.0.0.1:%d{{SVC_TOKEN}}/x" % self.port, {})
        self.assertEqual(code, 400)       # a placeholder inside the authority is refused at creation
        self.assert_no_leak("evil.example")


class TemplateRefusedAtCreation(HttpBase):
    """The agent's own text: control characters are refused up front with a generic sentence."""

    def refused(self, **kw):
        t.Echo.hits.clear()
        code, got, _ = self.go(**kw)
        self.assertEqual(code, 400, got)
        self.assertEqual(t.Echo.hits, [])
        self.assertNotIn(CORE, json.dumps(got))
        return got

    def test_report_1_exact_repro_is_refused(self):
        got = self.refused(headers={"Authorization": "token {{SVC_TOKEN}}\r\nX: y"})
        self.assertNotIn("\r", got["error"])
        self.assertNotIn("SVC_TOKEN", got["error"])
        self.assert_no_leak()
        self.assertEqual(self.events("approved"), [])      # no card was ever raised
        self.assertEqual(self.notifier.sent, [])

    def test_lf_cr_nul_del_in_value_template(self):
        for ch in ("\n", "\r", "\x00", "\x7f", "\x1b", "\x0b"):
            self.refused(headers={"X-A": "a" + ch + "b {{SVC_TOKEN}}"})

    def test_control_char_inside_a_placeholder(self):
        self.refused(headers={"Authorization": "Bearer {{\r\nSVC_TOKEN}}"})
        self.refused(headers={"Authorization": "Bearer {{SVC_TOKEN\n}}"})
        self.refused(headers={"Authorization": "Bearer {{ SVC_TOKEN\x00 }}"})

    def test_bad_header_names(self):
        for name in ("X A", "X\r\nY", "X:Y", "", "X\x00", "Xé", " X", "X ", "X\tY", "a" * 300):
            self.refused(headers={name: "v"})

    def test_whitespace_and_controls_in_url(self):
        base = f"http://127.0.0.1:{self.port}"
        for u in (base + "/a b", base + "/a\r\nHost: x", base + "/a\tb", base + "/\x00", base + "/\x7f",
                  base + "/café", " " + base + "/x", base + "/x\n"):
            self.refused(url=u)

    def test_value_as_port_or_host_is_refused(self):
        self.refused(url="http://127.0.0.1:{{SVC_TOKEN}}/x")
        self.refused(url="http://{{SVC_TOKEN}}/x")
        self.refused(url=f"http://127.0.0.1:{self.port}@{{{{SVC_TOKEN}}}}/x")
        self.refused(url="{{SVC_TOKEN}}://127.0.0.1/x")

    def test_non_numeric_and_huge_port_in_template(self):
        self.refused(url="http://127.0.0.1:99999999/x")
        self.refused(url="http://127.0.0.1:abc/x")

    def test_spaces_in_values_and_placeholders_still_work(self):
        code, got, _ = self.go(headers={"Authorization": "token  {{ SVC_TOKEN }}", "X-Note": "a b\tc"})
        self.assertEqual((code, got["status"]), (200, "approved"), got)
        self.assertEqual(got["http"]["status"], 200)


class SettlePointsNeverRepeatText(HttpBase):
    """Whatever the release path raises, the request settles with a fixed label."""

    def tweak2(self, cfg):
        pass

    def boom(self, exc):
        def raiser(*a, **k):
            raise exc
        return raiser

    def exceptions(self):
        s = CORE
        return [ValueError("bad header " + s), http.client.InvalidURL("nonnumeric port: '" + s + "'"),
                OSError("oops " + s), socket.timeout("t " + s), KeyError(s), RuntimeError(s),
                UnicodeEncodeError("latin-1", s, 0, 1, "x " + s),
                urllib.error.URLError("failed " + s)]

    def test_human_approved_path(self):
        for exc in self.exceptions():
            with mock.patch("secret_broker.broker._do_http", self.boom(exc)):
                code, got, rid = self.go()
            self.assertEqual(got["status"], "failed", exc)
            self.assertRegex(got["error"], r"^release failed: (invalid request|connection|timeout|dns|tls|other|vault)$")
            self.assert_no_leak()

    def test_release_raising_anything_still_settles(self):
        for exc in self.exceptions():
            with mock.patch("secret_broker.broker.Broker._release", self.boom(exc)):
                code, got, rid = self.go(wait=5)
            self.assertEqual(got["status"], "failed", exc)
            self.assertNotIn(CORE, json.dumps(got))
            self.assert_no_leak()

    def test_exception_repr_and_traceback_of_a_release_failure(self):
        self.broker.backend._data["Svc"]["token"] = BAD_VALUES["crlf"]
        code, got, rid = self.go()
        req = self.broker._by_id[rid]
        try:
            self.broker._release(req)
        except Exception as e:      # noqa: BLE001
            texts = [repr(e), str(e), "".join(traceback.format_exception(type(e), e, e.__traceback__)),
                     repr(e.__cause__), repr(e.__context__)]
        else:
            self.fail("expected the release to fail")
        for x in texts:
            self.assertNotIn(CORE, x)

    def test_backend_error_on_vault_read_is_a_label(self):
        from secret_broker.backends import BackendError
        with mock.patch.object(self.broker.backend, "get", side_effect=BackendError("vault says " + CORE)):
            code, got, rid = self.go()
        self.assertEqual(got["error"], "release failed: vault")
        self.assert_no_leak()


class PolicyAutoPath(HttpBase):
    """approval: allow -> released by policy with no human: the same labels."""
    decision = None

    def tweak2(self, cfg):
        cfg["secrets"]["svc"]["approval"] = "allow"

    def setUp(self):
        super().setUp()
        self.broker.summarizer = t._Stub("Reads", "low")

    def test_auto_path_hostile_values(self):
        for name, value in BAD_VALUES.items():     # (a space is legal in a header value: path cases are above)
            self.broker.backend._data["Svc"]["token"] = value
            code, got, rid = self.go()
            self.assertEqual(got["status"], "failed", name)
            self.assertEqual(got["error"], "release failed: invalid request", name)
            self.assertEqual(self.events("failed")[-1]["via"], "policy")
            self.assert_no_leak()

    def test_auto_path_exception_text_never_used(self):
        for exc in (ValueError("v " + CORE), http.client.InvalidURL(CORE), OSError(CORE), RuntimeError(CORE)):
            with mock.patch("secret_broker.broker._do_http", side_effect=exc):
                code, got, rid = self.go()
            self.assertEqual(got["status"], "failed")
            self.assertNotIn(CORE, json.dumps(got))
            self.assert_no_leak()

    def test_auto_path_http_install_error_does_not_escape(self):
        # InvalidURL is not a ValueError and escaped the old handler: the request must still settle
        with mock.patch("secret_broker.broker._do_http", side_effect=http.client.InvalidURL(CORE)):
            code, got, rid = self.go()
        self.assertEqual(got["status"], "failed")


class TimedGrantPath(Everywhere, tg.Base):
    """A timed grant releases later requests without a human: the same settle rule."""
    grants_cfg = {"enabled": True, "durations": [15], "max_minutes": 60}

    def setUp(self):
        super().setUp()
        self._capture()
        self.seen_bodies = []

    def tearDown(self):
        self._stack.close()
        super().tearDown()

    def test_grant_release_failure_is_a_label(self):
        self.grant_it()
        for exc in (ValueError("v " + CORE), http.client.InvalidURL(CORE), OSError(CORE), RuntimeError(CORE)):
            with mock.patch("secret_broker.broker._do_http", side_effect=exc):
                rid = self.http()
                res = self.auto(rid)
            self.seen_bodies.append(json.dumps(res))
            self.assertEqual(res["status"], "failed", res)
            self.assertRegex(res["error"], r"^release failed: [a-z ]+$")
            self.assertEqual(self.events("failed")[-1]["via"], "policy")
        self.assert_no_leak()

    def test_grant_path_hostile_value(self):
        self.grant_it()
        self.broker.backend._data["Svc"]["token"] = BAD_VALUES["crlf"]
        res = self.auto(self.http())
        self.assertEqual(res["error"], "release failed: invalid request")
        self.assert_no_leak()


class EnvModeStructuredField(HttpBase):
    """env mode builds no headers, but it reads a key out of a structured field: a broken field's parser
    text can quote the field (which holds the secret), so it must be a label too."""
    value = '{"a": "x", "b": "' + CORE + '" broken'

    def tweak2(self, cfg):
        cfg["secrets"]["svc"]["vars"]["SVC_TOKEN"]["key"] = "a"

    def test_broken_structured_field_does_not_echo_the_field(self):
        code, body = self.create_env()
        self.seen_bodies.append(body)
        rid = json.loads(body)["id"]
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        self.seen_bodies.append(b)
        got = json.loads(b)
        self.assertEqual(got["status"], "failed")
        self.assertEqual(got["error"], "release failed: vault")
        self.assert_no_leak()


class ErrClassUnit(unittest.TestCase):
    def test_labels_are_a_closed_set(self):
        from secret_broker import errclass
        cases = [(socket.timeout(), "timeout"), (socket.gaierror(), "dns"), (OSError(), "connection"),
                 (ConnectionRefusedError(), "connection"), (ValueError("x"), "invalid request"),
                 (http.client.InvalidURL("x"), "invalid request"), (RuntimeError(), "other"),
                 (urllib.error.URLError(socket.timeout()), "timeout")]
        for exc, want in cases:
            self.assertEqual(errclass.classify(exc), want)
            self.assertIn(errclass.classify(exc), errclass.LABELS)


class SessionLeaks(Everywhere, ts.SBase):
    """HTTP sessions: the same hostile values, through the real session endpoints."""

    def setUp(self):
        super().setUp()
        self._capture()
        self.seen_bodies = []

    def tearDown(self):
        self._stack.close()
        super().tearDown()

    def call_with(self, cred, **kw):
        sid = self.open(cred=cred)
        code, r = self.call(sid, "GET", "/echo", names=(cred,), **kw)
        self.seen_bodies.append(json.dumps(r))
        return code, r

    def test_space_value_in_path(self):
        self.broker.backend._data["Spacecred"]["token"] = SPACE
        code, r = self.call_with("spacecred", url=self.url("/p/{{SPACECRED_TOKEN}}"))
        self.assertEqual(r["status"], "failed", r)
        self.assertEqual(r["error"], "upstream call failed (invalid request)")
        self.assert_no_leak()

    def test_crlf_value(self):
        self.broker.backend._data["Crlfcred"]["token"] = CORE + "\r\nX: y"
        code, r = self.call_with("crlfcred", headers={"X-CSRF-Token": "{{CRLFCRED_TOKEN}}"})
        self.assertEqual(r["error"], "upstream call failed (invalid request)")
        self.assert_no_leak()

    def test_non_ascii_value(self):
        self.broker.backend._data["Spacecred"]["token"] = CORE + "☃"
        code, r = self.call_with("spacecred", headers={"X-CSRF-Token": "{{SPACECRED_TOKEN}}"})
        self.assertEqual(r["error"], "upstream call failed (invalid request)")
        self.assert_no_leak()

    def test_value_as_port_is_never_sent(self):
        self.broker.backend._data["Spacecred"]["token"] = "80@evil.example"
        sid = self.open(cred="spacecred")
        code, r = self.call(sid, "GET", "/", names=("spacecred",), url="http://127.0.0.1:{{SPACECRED_TOKEN}}/")
        self.assertNotEqual(r.get("status"), "approved", r)
        self.assertEqual(self.st["seen"], [])

    def test_exception_text_never_used(self):
        sid = self.open(cred="spacecred")
        for exc in (ValueError(CORE), http.client.InvalidURL(CORE), OSError(CORE), RuntimeError(CORE)):
            class Boom:
                def open(self, req, timeout=None, _e=exc):
                    raise _e
            with mock.patch("secret_broker.broker._opener_for", lambda tls, *a, **k: Boom()):
                code, r = self.call(sid, "GET", "/", names=("spacecred",))
            self.seen_bodies.append(json.dumps(r))
            self.assertEqual(r["status"], "failed")
            self.assertNotIn(CORE, r["error"])
        self.assert_no_leak()


class PlanLeaks(Everywhere, pb.PBase):
    def setUp(self):
        super().setUp()
        self._capture()
        self.seen_bodies = []

    def tearDown(self):
        self._stack.close()
        super().tearDown()

    def run_value(self, value, pid=None, **kw):
        self.broker.backend._data["Svc"]["token"] = value
        code, r = self.call(pid, "svc", "GET", "/v1/accounts/1", **kw)
        self.seen_bodies.append(json.dumps(r))
        return pid, code, r

    def test_hostile_values_never_come_back(self):
        pid = self.approve(self.manifest([self.read_rule()]))
        for name, value in BAD_VALUES.items():
            pid, code, r = self.run_value(value, pid)
            self.assertNotEqual(r.get("status"), "approved", name)
            self.assertNotIn(CORE, json.dumps(r))
        self.assertEqual(self.upstream(), [])
        self.assert_no_leak()

    def test_exception_text_never_used(self):
        pid = self.approve(self.manifest([self.read_rule()]))
        for exc in (ValueError(CORE), http.client.InvalidURL(CORE), OSError(CORE), RuntimeError(CORE)):
            class Boom:
                def open(self, req, timeout=None, _e=exc):
                    raise _e
            with mock.patch("secret_broker.broker._opener_for", lambda tls, *a, **k: Boom()):
                code, r = self.call(pid, "svc", "GET", "/v1/accounts/1")
            self.seen_bodies.append(json.dumps(r))
            self.assertNotIn(CORE, json.dumps(r))
            self.assertEqual(r.get("status"), "failed", r)
        self.assert_no_leak()


class SshRulePath(Everywhere, tr.Base):
    """A standing SSH rule releases without a human: its settle point must also report a label only."""
    ssh_hosts = tr.KNOWN
    rules = [tr.R(tr.HOST, "deploy", label="web.example.com")]

    def setUp(self):
        super().setUp()
        self._capture()
        self.seen_bodies = []

    def tearDown(self):
        self._stack.close()
        super().tearDown()

    def test_rule_release_failure_is_a_label(self):
        for exc in (ValueError("v " + CORE), http.client.InvalidURL(CORE), OSError(CORE), RuntimeError(CORE)):
            with mock.patch("secret_broker.broker.Broker._release", side_effect=exc):
                rid = self.ask_ok(tr.login(tr.SID_A), [tr.HOST.bind(tr.SID_A)])
                res = self.result(rid)
            self.seen_bodies.append(json.dumps(res))
            self.assertEqual(res["status"], "failed")
            self.assertRegex(res["error"], r"^release failed: [a-z ]+$")
            self.assertNotIn(CORE, json.dumps(res))
        self.assert_no_leak()


if __name__ == "__main__":
    unittest.main()

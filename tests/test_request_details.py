"""Request details: headers and body on the approval card and page, masking, the
retained history copy (separate store), retention, caps, config and leak checks."""
import base64
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import test_e2e  # noqa: E402
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import audit_api, broker as broker_mod, request_details as D, scripts as S  # noqa: E402
from secret_broker.backends import FileBackend  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

CRED = "LITERALCRED_canary_9f3a"
BODYC = "BODYCANARY_77c1"
HDR = {"X-authentik-username": "alice"}
SCRIPT_TEXT = "#!/bin/sh\n" + "echo line\n" * 600


def spec(headers=None, body=None, body_b64=None, method="PUT", url="http://127.0.0.1/x"):
    return {"method": method, "url": url, "headers": headers or {}, "body": body, "body_b64": body_b64}


class Base(test_e2e.Harness):
    decision = None             # leave requests pending so cards can be read
    rd = None                   # request_details config tweak

    def tweak(self, cfg):
        if self.rd is not None:
            cfg["request_details"] = self.rd

    def post(self, headers=None, body=None, body_b64=None, method="PUT", **extra):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        payload = {"mode": "http", "names": ["svc"], "method": method, "url": url,
                   "headers": {"Authorization": "Bearer {{SVC_TOKEN}}", **(headers or {})}}
        if body is not None:
            payload["body"] = body
        if body_b64 is not None:
            payload["body_b64"] = body_b64
        payload.update(extra)
        code, out = self.api("POST", "/v1/requests", payload)
        self.assertEqual(code, 202, out)
        return json.loads(out)["id"]

    def req_of(self, rid):
        return self.broker._by_id[rid]

    def card(self, rid):
        return test_e2e.req(self.abase + f"/a/{self.req_of(rid).nonce}", headers=HDR)[1]

    def dash(self):
        return test_e2e.req(self.abase + "/", headers=HDR)[1]

    def popover(self, rid):
        return test_e2e.req(self.abase + f"/request/{rid}?fragment=1", headers=HDR)


class CardTests(Base):
    def test_card_has_collapsed_details_with_headers_and_body(self):
        rid = self.post({"Content-Type": "text/plain", "X-Trace": "abc"}, body="hello {{SVC_TOKEN}} world")
        for page in (self.card(rid), self.dash()):
            self.assertIn("<details class=reqdetails><summary>Request details</summary>", page)
            self.assertNotIn("<details class=reqdetails open", page)
            self.assertIn("Authorization: Bearer {{SVC_TOKEN}}", page)      # placeholder shown, not substituted
            self.assertIn("X-Trace: abc", page)
            self.assertIn("hello {{SVC_TOKEN}} world", page)
            self.assertIn("text/plain, 25 bytes", page)
            self.assertNotIn(test_e2e.SECRET, page)
        self.assertIn(f"data-id='{rid}'", self.dash())      # the key the poll uses to restore the open state

    def test_shown_is_what_is_sent(self):
        rid = self.post({"X-Foo-Token": CRED}, body="x")
        sp = self.req_of(rid).spec
        self.assertEqual(sp["headers"]["X-Foo-Token"], CRED)       # the executed spec is untouched
        page = self.card(rid)
        self.assertIn("X-Foo-Token: [masked]", page)
        self.assertNotIn(CRED, page)
        self.assertNotIn(CRED, self.dash())

    def test_body_cap_and_truncation_note(self):
        rid = self.post({"Content-Type": "text/plain"}, body="x" * 5000)
        page = self.card(rid)
        self.assertIn("truncated, 5000 bytes total", page)
        self.assertIn("x" * 2048, page)
        self.assertNotIn("x" * 2049, page)

    def test_multibyte_cut_stays_valid(self):
        rid = self.post({"Content-Type": "text/plain"}, body="é" * 2000)
        page = self.card(rid)
        self.assertIn("truncated, 4000 bytes total", page)
        self.assertIn("é" * 1024, page)
        self.assertNotIn("é" * 1025, page)

    def test_json_is_formatted_for_display_only(self):
        raw = '{"a":1,"b":[1,2],"c":{"d":"e"}}'
        rid = self.post({"Content-Type": "application/json"}, body=raw)
        page = self.card(rid)
        self.assertIn('  &quot;a&quot;: 1,' if '&quot;' in page else '  "a": 1,', page)
        self.assertIn("formatted for display; the bytes sent are unchanged", page)
        self.assertEqual(self.req_of(rid).spec["body"], raw)         # sent as the agent supplied it

    def test_invalid_json_shown_as_is(self):
        rid = self.post({"Content-Type": "application/json"}, body='{"a":')
        page = self.card(rid)
        self.assertIn("{&quot;a&quot;:" if "&quot;" in page else '{"a":', page)
        self.assertNotIn("formatted for display", page)

    def test_binary_shows_type_and_length_only(self):
        raw = b"\x00\x01BINMARKER\xff\xfe"
        rid = self.post({"Content-Type": "application/octet-stream"}, body_b64=base64.b64encode(raw).decode())
        page = self.card(rid)
        self.assertIn("application/octet-stream, 13 bytes", page)
        self.assertIn("binary or non-text content is not shown", page)
        self.assertNotIn("BINMARKER", page)
        # no content type but not text either
        rid2 = self.post(body_b64=base64.b64encode(b"ab\x00cd").decode())
        self.assertNotIn("ab\x00cd", self.card(rid2))
        self.assertIn("5 bytes", self.card(rid2))
        # a text-looking body under a non-text content type is not shown either
        rid3 = self.post({"Content-Type": "image/png"}, body="NOTSHOWN_TEXT")
        self.assertNotIn("NOTSHOWN_TEXT", self.card(rid3))

    def test_no_content_type_text_body_is_shown(self):
        rid = self.post(body="plain words")
        self.assertIn("plain words", self.card(rid))

    def test_hostile_text_is_escaped(self):
        hostile = "<script>alert(1)</script>\n<img src=x onerror=alert(2)>\n" + "A" * 3000 + "\x1b[2J</pre><details open>"
        # (control characters and markup in a header NAME or value are refused at creation now; the body is free text)
        rid = self.post({"Content-Type": "text/html", "X-Evil": "<b>bold</b></pre>",
                         "X-Long": "L" * 4000}, body=hostile)
        for page in (self.card(rid), self.dash()):
            for bad in ("<script>alert(1)", "<img src=x", "<b>bold</b>", "X-Line<br>", "\x1b", "\x07", "<details open>"):
                self.assertNotIn(bad, page, bad)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
            self.assertNotIn("L" * 501, page)
            self.assertIn("long values cut at 500 characters", page)
            self.assertEqual(page.count("<details class=reqdetails>"), 1)

    def test_header_count_cap(self):
        hs = {f"X-H{i}": "v" for i in range(60)}
        rid = self.post(hs)
        page = self.card(rid)
        self.assertIn("first 40 shown", page)
        self.assertIn("X-H38: v", page)
        self.assertNotIn("X-H45", page)

    def test_omitted_without_headers_or_body(self):
        self.assertEqual(D.html(D.build_view(spec())), "")
        self.assertEqual(D.html(None), "")

    def test_only_http_mode_has_details(self):
        code, out = self.create_env()
        self.assertEqual(code, 202)
        self.assertNotIn("Request details", self.card(json.loads(out)["id"]))

    def test_scrub_withheld_fallback(self):
        rid = self.post({"Content-Type": "text/plain"}, body="somebody " + CRED)
        with mock.patch.object(S, "scrub", return_value=S.WITHHELD):
            v = D.build_view(self.req_of(rid).spec)
        self.assertEqual(v["body"]["kind"], "withheld")
        self.assertIn("[body withheld: could not be scrubbed safely]", D.html(v))
        self.assertNotIn(CRED, json.dumps(v))
        with mock.patch.object(S, "scrub", side_effect=RuntimeError("x")):
            self.assertEqual(D.build_view(spec({"Content-Type": "text/plain"}, body="a"))["body"]["kind"], "withheld")

    def test_body_secrets_are_scrubbed(self):
        v = D.build_view(spec({"Content-Type": "application/json"},
                              body=json.dumps({"password": "hunter2hunter2", "note": "ok"})))
        self.assertNotIn("hunter2hunter2", json.dumps(v))
        self.assertIn("ok", v["body"]["text"])
        v = D.build_view(spec({"Content-Type": "text/plain"}, body="x" * 2040 + " ghp_" + "a" * 36))
        self.assertNotIn("ghp_a", json.dumps(v))


class JsonDisplay(unittest.TestCase):
    WARN = "This JSON has duplicate keys or numbers that would change when formatted, so it is shown exactly as sent."

    def view(self, body):
        return D.build_view(spec({"Content-Type": "application/json"}, body=body))["body"]

    def test_hazards_show_raw_with_warning(self):
        cases = {
            '{"op":"read","op":"delete"}': "duplicate keys",
            '{"a":{"x":1,"y":2,"x":3}}': "duplicate keys",
            '[{"k":1},{"k":1,"k":2}]': "duplicate keys",
            '{"n":1.0000000000000001}': "unusual numbers",
            '{"n":1e400}': "unusual numbers",
            '{"n":123456789012345678901234567890}': "unusual numbers",
            '{"n":NaN}': "unusual numbers",
            '[-Infinity]': "unusual numbers",
            '[Infinity]': "unusual numbers",
        }
        for raw, what in cases.items():
            b = self.view(raw)
            self.assertEqual(b["text"], raw, raw)
            self.assertFalse(b["formatted"], raw)
            self.assertIn(what, b["warn"], raw)
            self.assertNotIn("raw", b)
            page = D.html({"headers": [], "body": b, "ctype": "application/json"})
            self.assertIn(self.WARN, page)
            self.assertIn(what, page)
            self.assertNotIn("formatted for display", page)
            self.assertNotIn("Show as sent", page)

    def test_both_warnings_named(self):
        self.assertEqual(self.view('{"a":1,"a":2,"b":1e999}')["warn"], ["duplicate keys", "unusual numbers"])

    def test_deep_nesting_falls_back_to_raw(self):
        raw = "[" * 100000 + "]" * 100000
        b = self.view(raw)       # too deep: must not raise
        self.assertEqual(b["kind"], "text")
        self.assertFalse(b["formatted"])
        self.assertTrue(b["text"].startswith("[[[["))
        self.assertNotIn("warn", b)

    def test_clean_json_is_formatted_with_as_sent_toggle(self):
        raw = '{"a":1,"b":[1.5,2],"c":0.1,"d":"x"}'
        b = self.view(raw)
        self.assertTrue(b["formatted"])
        self.assertEqual(b["raw"], raw)
        self.assertIn('  "a": 1', b["text"])
        page = D.html({"headers": [], "body": b, "ctype": "application/json"})
        self.assertIn("formatted for display", page)
        self.assertIn("<details class=asent><summary>Show as sent</summary>", page)
        self.assertNotIn("<details class=asent open", page)
        self.assertNotIn(self.WARN, page)

    def test_raw_is_capped_and_scrubbed_too(self):
        b = self.view('{"password":"hunter2hunter2","k":"' + "v" * 5000 + '"}')
        self.assertNotIn("hunter2hunter2", json.dumps(b))
        self.assertLessEqual(len(b["raw"].encode()), 2048)
        self.assertLessEqual(len(b["text"].encode()), 2048)


class Masking(unittest.TestCase):
    def test_listed_headers_masked_unless_placeholders(self):
        names = ["Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Api-Secret",
                 "X-Auth-Token", "X-Access-Token", "X-Foo-Token", "x-my-password", "X-Credential-Id", "X-Some-Key",
                 "X-Client-Secret"]
        for n in names:
            v = D.build_view(spec({n: CRED}))
            self.assertEqual(v["headers"], [[n, "[masked]"]], n)
            v = D.build_view(spec({n: "Bearer " + CRED}))
            self.assertEqual(v["headers"], [[n, "[masked]"]], n)
            for ok in ("{{SVC_TOKEN}}", "Bearer {{SVC_TOKEN}}", "Basic {{ USER }}:{{PASS}}"):
                self.assertEqual(D.build_view(spec({n: ok}))["headers"], [[n, ok]], (n, ok))

    def test_literal_mixed_with_placeholder_is_masked(self):
        for bad in ("Bearer " + CRED + "{{SVC_TOKEN}}", "sk-live-123 {{SVC_TOKEN}}", "Bearer {{A}} " + CRED, "",
                    "session={{SID}}", "{{A"):
            self.assertEqual(D.build_view(spec({"Authorization": bad}))["headers"][0][1], "[masked]", bad)

    def test_other_headers_are_shown_in_full(self):
        v = D.build_view(spec({"X-Trace": CRED, "Accept": "application/json"}))
        self.assertEqual(v["headers"], [["X-Trace", CRED], ["Accept", "application/json"]])


class JsOpenState(unittest.TestCase):
    HARNESS = r"""
const fs=require('fs');
eval(fs.readFileSync(process.argv[2],'utf8')+';global.o=asbOpenKeys;global.r=asbReopen;');
function det(cls,open){return {className:cls,open:!!open};}
function art(id,ds){return {getAttribute:(k)=>k==='data-id'?id:null,
  querySelectorAll:(sel)=>ds.filter(d=>sel.split(',').some(s=>s.trim()==='details.'+d.className))};}
function root(as){return {querySelectorAll:(sel)=>sel==='article[data-id]'?as:[]};}
const before=root([art('A',[det('reqdetails',true),det('scripts',false)]),art('B',[det('reqdetails',false)]),
  art('C',[det('scripts',true)])]);
const keys=o(before);
const after=root([art('A',[det('reqdetails',false),det('scripts',false)]),art('B',[det('reqdetails',false)]),
  art('D',[det('reqdetails',false)]),art('C',[det('scripts',false)])]);
r(after,keys);
const st=after.querySelectorAll('article[data-id]').map(a=>a.querySelectorAll('details.reqdetails,details.scripts'));
console.log(JSON.stringify({keys,A:st[0].map(d=>d.open),B:st[1].map(d=>d.open),D:st[2].map(d=>d.open),C:st[3].map(d=>d.open)}));
"""

    def test_open_details_survive_a_card_refresh(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "keep.js"), "w") as f:
            f.write(broker_mod._KEEP_JS)
        with open(os.path.join(d, "h.js"), "w") as f:
            f.write(self.HARNESS)
        r = subprocess.run([node, os.path.join(d, "h.js"), os.path.join(d, "keep.js")],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(len(out["keys"]), 2)
        self.assertEqual((out["A"], out["B"], out["D"], out["C"]), ([True, False], [False], [False], [True]))

    def test_poll_records_before_and_restores_after_replacing(self):
        js = broker_mod._DASH_JS
        a, b, c = (js.index(x) for x in ("asbOpenKeys(cards)", "cards.innerHTML=c.innerHTML", "asbReopen(cards,wasopen)"))
        self.assertTrue(a < b < c)
        self.assertIn("function asbReopen", js)


class History(Base):
    decision = "approve"

    def finish(self, headers=None, body=None, **kw):
        rid = self.post(headers, body, **kw)
        self.api("GET", f"/v1/requests/{rid}?wait=5")
        return rid

    def test_popover_shows_retained_details(self):
        rid = self.finish({"Content-Type": "application/json", "X-Foo-Token": CRED},
                          body=json.dumps({"note": BODYC}))
        code, page = self.popover(rid)
        self.assertEqual(code, 200)
        self.assertIn("<details class=reqdetails><summary>Request details</summary>", page)
        self.assertIn(BODYC, page)
        self.assertIn("Authorization: Bearer {{SVC_TOKEN}}", page)
        self.assertIn("X-Foo-Token: [masked]", page)
        self.assertNotIn(CRED, page)

    def test_store_file_is_owner_only_and_holds_no_literal_credential(self):
        rid = self.finish({"X-Foo-Token": CRED}, body=BODYC)
        path = self.broker.details._path
        self.assertEqual(os.path.dirname(path), os.path.dirname(self.audit))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, "rb") as f:
            raw = f.read()
        self.assertNotIn(CRED.encode(), raw)
        self.assertIn(BODYC.encode(), raw)
        rec, state = self.broker.details.get(rid)
        self.assertEqual(state, "ok")
        self.assertEqual(rec["body"]["text"], BODYC)

    def test_binary_is_not_retained(self):
        raw = b"\x00\x01RETAINMARK\xff"
        rid = self.finish({"Content-Type": "application/octet-stream"}, body_b64=base64.b64encode(raw).decode())
        rec, state = self.broker.details.get(rid)
        self.assertEqual(rec["body"], {"kind": "binary", "total": len(raw)})
        with open(self.broker.details._path, "rb") as f:
            blob = f.read()
        self.assertNotIn(b"RETAINMARK", blob)
        self.assertNotIn(base64.b64encode(raw), blob)
        self.assertIn("application/octet-stream, %d bytes" % len(raw), self.popover(rid)[1])

    def test_retained_body_is_capped(self):
        rid = self.finish({"Content-Type": "text/plain"}, body="y" * 5000)
        rec, _ = self.broker.details.get(rid)
        self.assertEqual(len(rec["body"]["text"]), 2048)
        self.assertEqual(rec["body"]["total"], 5000)
        self.assertIn("truncated, 5000 bytes total", self.popover(rid)[1])

    def test_expired_entries_are_not_shown(self):
        rid = self.finish({"Content-Type": "text/plain"}, body=BODYC)
        self.broker.details._clock = lambda: time.time() + 8 * 86400
        page = self.popover(rid)[1]
        self.assertNotIn(BODYC, page)
        self.assertIn("Details are kept for 7 days and have expired.", page)

    def test_missing_entry_for_old_request_reads_as_expired(self):
        rid = self.finish(body="z")
        self.broker.details._run("t", lambda c: c.execute("DELETE FROM details"))
        self.assertIn("not available", self.popover(rid)[1])
        with mock.patch("secret_broker.broker.time.time", return_value=time.time() + 9 * 86400):
            self.assertIn("have expired", self.popover(rid)[1])

    def test_corrupt_store_means_no_details_and_an_audit_warning(self):
        rid = self.finish(body=BODYC)
        with open(self.broker.details._path, "wb") as f:
            f.write(b"this is not a database " * 50)
        code, page = self.popover(rid)
        self.assertEqual(code, 200)
        self.assertNotIn(BODYC, page)
        self.assertIn("not available", page)
        ev = self.events("request_details_store_error")
        self.assertTrue(ev)
        self.assertEqual(set(ev[0]) - {"seq", "ts", "time", "event", "prev"}, {"op", "error"})
        self.assertNotIn(BODYC, json.dumps(ev))
        # the store recovers for new requests
        rid2 = self.finish(body="after corruption")
        self.assertEqual(self.broker.details.get(rid2)[1], "ok")

    def test_missing_store_file_is_tolerated(self):
        rid = self.finish(body=BODYC)
        os.unlink(self.broker.details._path)
        code, page = self.popover(rid)
        self.assertEqual(code, 200)
        self.assertNotIn(BODYC, page)

    def test_env_scripts_are_retained_and_capped(self):
        text = SCRIPT_TEXT
        entry = {"path": "/srv/job.sh", "size": len(text), "sha256": "a" * 64, "text": text, "truncated": False}
        code, out = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["sh", "/srv/job.sh"],
                                                      "scripts": [entry, {"stdin": True}]})
        rid = json.loads(out)["id"]
        self.api("GET", f"/v1/requests/{rid}?wait=5")
        rec, state = self.broker.details.get(rid)
        self.assertEqual(state, "ok")
        self.assertEqual(len(rec["scripts"][0]["text"].encode()), 4096)
        self.assertTrue(rec["scripts"][0]["truncated"])
        page = self.popover(rid)[1]
        self.assertIn("Script contents (reported by the client)", page)
        self.assertIn("echo line", page)
        self.assertIn("Only the start of this script is shown", page)


class SmallCaps(Base):
    rd = {"max_body_bytes": 100, "max_script_bytes": 30}

    def test_configured_caps(self):
        rid = self.post({"Content-Type": "text/plain"}, body="q" * 500)
        self.assertIn("q" * 100, self.card(rid))
        self.assertNotIn("q" * 101, self.card(rid))
        entry = {"path": "/s.sh", "size": 100, "sha256": "b" * 64, "text": "w" * 100, "truncated": False}
        _, out = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["sh", "s"],
                                                   "scripts": [entry]})
        rec, _ = self.broker.details.get(json.loads(out)["id"])
        self.assertEqual(rec["scripts"][0]["text"], "w" * 30)


class Disabled(Base):
    decision = "approve"
    rd = {"enabled": False}

    def test_nothing_stored_or_shown(self):
        rid = self.post({"X-Foo-Token": CRED}, body=BODYC)
        self.api("GET", f"/v1/requests/{rid}?wait=5")
        self.assertIsNone(self.broker.details)
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.audit), "request_details.db")))
        self.assertNotIn("Request details</summary>", self.popover(rid)[1])
        self.assertNotIn(BODYC, self.popover(rid)[1])

    def test_card_has_no_section(self):
        self.decision = None
        rid = self.post(body=BODYC)
        self.assertNotIn(BODYC, self.card(rid))
        self.assertNotIn("class=reqdetails", self.card(rid))


class Store(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "request_details.db")
        self.now = [1000.0]
        self.errs = []
        self.cfg = D.parse_config({"max_store_mb": 1, "retention_days": 2})
        self.s = D.DetailsStore(self.path, self.cfg, lambda e, **k: self.errs.append((e, k)),
                                clock=lambda: self.now[0])

    def test_put_get_expiry_and_sweep(self):
        self.assertTrue(self.s.put("r1", {"headers": [], "body": None}))
        self.assertEqual(self.s.get("r1")[1], "ok")
        self.now[0] += 86400
        self.assertTrue(self.s.put("r2", {"headers": [["a", "b"]]}))
        self.now[0] += 86400 + 1                     # r1 is past 2 days, r2 is not
        self.assertEqual(self.s.get("r1"), (None, "expired"))
        self.assertEqual(self.s.get("r2")[1], "ok")
        self.assertEqual(self.s.get("nope"), (None, "missing"))
        self.assertEqual(self.s.sweep(), 1)
        self.assertEqual(self.s.get("r1"), (None, "missing"))
        self.assertEqual(self.s.count(), 1)
        self.assertEqual(self.s.sweep(), 0)

    def test_size_cap_evicts_oldest_first(self):
        blob = "a" * 400_000
        for i in range(4):
            self.now[0] += 1
            self.s.put(f"r{i}", {"x": blob})
        self.assertEqual(self.s.get("r0")[1], "missing")
        self.assertEqual(self.s.get("r1")[1], "missing")
        self.assertEqual(self.s.get("r2")[1], "ok")
        self.assertEqual(self.s.get("r3")[1], "ok")

    def test_startup_sweep_runs_on_a_daemon_thread(self):
        self.s.put("old", {"x": 1})
        self.now[0] += 3 * 86400
        t = self.s.start(interval=3600)
        self.assertTrue(t.daemon)
        for _ in range(100):
            if self.s.count() == 0:
                break
            time.sleep(0.05)
        self.s.stop()
        self.assertEqual(self.s.count(), 0)

    def test_permissions_and_directory_file(self):
        self.s.put("r", {"x": 1})
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_corrupt_file_never_raises(self):
        with open(self.path, "wb") as f:
            f.write(b"garbage" * 100)
        self.assertEqual(self.s.get("r"), (None, "missing"))   # set aside, fresh file, nothing there
        self.assertTrue(self.errs and self.errs[0][0] == "request_details_store_error")
        self.assertEqual(set(self.errs[0][1]), {"op", "error"})
        self.assertTrue(os.path.exists(self.path + ".corrupt"))
        self.assertTrue(self.s.put("r", {"x": 1}))
        # an unwritable location is reported, not raised
        bad = D.DetailsStore(os.path.join(self.d, "nodir", "x.db"), self.cfg, lambda e, **k: self.errs.append(e))
        self.assertFalse(bad.put("r", {"x": 1}))
        self.assertEqual(bad.get("r"), (None, "error"))
        self.assertEqual(bad.sweep(), 0)


class Config(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(D.parse_config(None), {"enabled": True, "retention_days": 7, "max_body_bytes": 2048,
                                                "max_script_bytes": 4096, "max_store_mb": 20})
        self.assertEqual(D.parse_config({"retention_days": 30})["retention_days"], 30)

    def test_bad_values_name_the_field(self):
        for bad, field in (({"retention_days": 0}, "retention_days"), ({"retention_days": 91}, "retention_days"),
                           ({"retention_days": "7"}, "retention_days"), ({"retention_days": True}, "retention_days"),
                           ({"max_body_bytes": -1}, "max_body_bytes"), ({"max_script_bytes": 1.5}, "max_script_bytes"),
                           ({"max_store_mb": 0}, "max_store_mb"), ({"enabled": "yes"}, "enabled"),
                           ({"bogus": 1}, "bogus")):
            with self.assertRaises(ValueError) as cm:
                D.parse_config(bad)
            self.assertIn(f"request_details.{field}", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            D.parse_config([])
        self.assertIn("request_details", str(cm.exception))

    def test_broker_init_validates(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "v.json"), "w") as f:
            f.write("{}")
        cfg = {"approve_base_url": "https://x", "allowed_user": "a", "request_details": {"retention_days": 500}}
        with self.assertRaises(ValueError) as cm:
            Broker(cfg, FileBackend(os.path.join(d, "v.json")), FakeNotifier(), os.path.join(d, "a.jsonl"))
        self.assertIn("request_details.retention_days", str(cm.exception))

    def test_main_validates_at_startup(self):
        d = tempfile.mkdtemp()
        cfg = {"request_details": {"max_store_mb": 0}, "backend": {"type": "file", "path": "x"}}
        r = subprocess.run([sys.executable, "-m", "secret_broker"], capture_output=True, text=True, cwd=os.path.join(HERE, ".."),
                           env={**os.environ, "BROKER_CONFIG": json.dumps(cfg)})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("request_details.max_store_mb", r.stderr)


class Canary(Base):
    """Headers and bodies reach only the approver pages."""
    decision = "approve"

    def raw_audit(self):
        with open(self.audit) as f:
            return f.read()

    def test_canaries_only_on_approver_surfaces(self):
        body = json.dumps({"canary": BODYC})
        rid = self.post({"Content-Type": "application/json", "X-Foo-Token": CRED}, body=body)
        code, result = self.api("GET", f"/v1/requests/{rid}?wait=10")
        self.assertEqual(code, 200)
        surfaces = {
            "result": result,
            "notifications": json.dumps(self.notifier.sent, default=str)
            + json.dumps([vars(n) for n in self.notifier.notifications], default=str)
            + json.dumps([(t, s) for t, s in self.notifier.resolutions]),
            "audit file": self.raw_audit(),
            "audit api": self.api("GET", "/v1/audit?limit=500")[1],
            "audit verify": self.api("GET", "/v1/audit/verify")[1],
            "discovery": self.api("GET", "/v1/secrets?host=127.0.0.1")[1],
            "status": self.api("GET", "/v1/status")[1],
            "history list": test_e2e.req(self.abase + "/?view=all", headers=HDR)[1],
            "history row": json.dumps(self.broker.history.rows(), default=str),
        }
        for name, text in surfaces.items():
            self.assertNotIn(BODYC, text, name)
            self.assertNotIn(CRED, text, name)
        self.assertTrue(self.events("requested"))
        # the approver pop-over does show the body, with the credential masked
        page = self.popover(rid)[1]
        self.assertIn(BODYC, page)
        self.assertIn("X-Foo-Token: [masked]", page)
        self.assertNotIn(CRED, page)

    def test_store_is_not_readable_by_the_agent_key(self):
        rid = self.post(body=BODYC)
        for path in (f"/request/{rid}", f"/request_details.db", "/v1/details"):
            code, text = self.api("GET", path)
            self.assertNotIn(BODYC, text)
        # approver pages require the SSO user
        code, text = test_e2e.req(self.abase + f"/request/{rid}?fragment=1", headers={"X-authentik-username": "mallory"})
        self.assertEqual(code, 403)
        self.assertNotIn(BODYC, text)

    def test_every_new_audit_event_is_hidden_from_the_agent(self):
        self.assertIn("request_details_store_error", audit_api.HIDDEN)


if __name__ == "__main__":
    unittest.main()

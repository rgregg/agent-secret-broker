"""Literal {{ }} in a request body (issue #55).

Only {{CREDENTIAL_VAR}} (UPPER_SNAKE) and {{session.NAME}} are placeholders; every other {{...}} in a body, such as
a Jinja/Handlebars template, is sent literally. `{{{{` is an escape for a literal `{{`, so a body can also carry
a pair that WOULD look like a placeholder. One scanner decides, so the approval card, the scope checks and the
send can never disagree about what is a placeholder.
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _fast  # noqa: F401,E402
import test_e2e as t  # noqa: E402
from secret_broker import broker as B, sessions as S  # noqa: E402

TEMPLATES = [
    "{{ states('sensor.x') }}",
    "{{ 1 + 1 }}",
    "{{ now }}",
    "{{ states.sensor.x.state }}",
    "{{ trigger.to_state.state | float }}",
    "{{name}}",
    "{{ }}",
    "{{}}",
    "{{{ raw }}}",
    '{"template": "{{ states(\'sensor.x\') }}"}',
]


class Scanner(unittest.TestCase):
    def test_non_credential_braces_are_literal_everywhere(self):
        for text in TEMPLATES:
            with self.subTest(text=text):
                self.assertEqual(S.placeholders(text), [])
                self.assertEqual(S.fill(text, {}), text)
                self.assertEqual(S.neutralize(text), text)     # the scope checks scan what is sent
                self.assertEqual(B._placeholders(text), [])
                self.assertEqual(B._fill(text, {}), text)

    def test_credential_and_session_placeholders_still_work(self):
        text = "a {{TOKEN}} b {{ TOKEN }} c {{session.Csrf}} d {{ session.Csrf }}"
        self.assertEqual(S.placeholders(text), ["TOKEN", "TOKEN", "session.Csrf", "session.Csrf"])
        vals = {"TOKEN": "T", "session.Csrf": "C"}
        self.assertEqual(S.fill(text, vals), "a T b T c C d C")
        self.assertEqual(B._placeholders("{{TOKEN}} {{ TOKEN }}"), ["TOKEN", "TOKEN"])
        self.assertEqual(B._fill("{{TOKEN}} {{ TOKEN }}", {"TOKEN": "T"}), "T T")

    def test_an_unknown_credential_shaped_name_is_still_an_error(self):
        with self.assertRaises(KeyError):                        # a typo must not be sent silently
            S.fill("{{TOKN}}", {"TOKEN": "T"})
        self.assertEqual(S.placeholders("{{TOKN}}"), ["TOKN"])

    def test_four_braces_escape_a_literal_pair(self):
        vals = {"TOKEN": "SECRET"}
        self.assertEqual(S.fill("{{{{ x }}", vals), "{{ x }}")
        self.assertEqual(S.fill("{{{{TOKEN}}", vals), "{{TOKEN}}")       # not substituted
        self.assertEqual(S.placeholders("{{{{TOKEN}}"), [])
        self.assertEqual(S.fill("{{{{ a }} {{TOKEN}}", vals), "{{ a }} SECRET")
        self.assertEqual(S.neutralize("{{{{TOKEN}}"), "{{TOKEN}}")
        self.assertEqual(B._fill("{{{{TOKEN}}", {"TOKEN": "SECRET"}), "{{TOKEN}}")
        self.assertEqual(B._placeholders("{{{{TOKEN}}"), [])

    def test_a_filled_value_is_never_scanned_again(self):
        self.assertEqual(S.fill("{{A}}", {"A": "{{B}}", "B": "x"}), "{{B}}")
        self.assertEqual(S.fill("{{A}}", {"A": "{{{{B}}"}), "{{{{B}}")

    def test_a_malformed_or_unclosed_pair_is_literal(self):
        for text in ("{{unclosed", "}} {{", "{{TOKEN", "TOKEN}}", "{{ TOKEN }", "}}}}"):
            with self.subTest(text=text):
                self.assertEqual(S.placeholders(text), [])
                self.assertEqual(S.fill(text, {"TOKEN": "T"}), text)

    def test_long_names_are_still_refused_not_sent_literally(self):
        self.assertEqual(S.placeholders("{{" + "P" * 100 + "}}"), ["\0toolong"])

    def test_scans_stay_linear(self):
        nasty = ["{{ " * 80000 + "}}", "{{" * 100000, "{{{{" * 50000, "{{" + "A" * 200000 + "}}", "}}" * 100000,
                 "{{ x " * 50000 + "}}"]
        t0 = time.time()
        for text in nasty:
            S.neutralize(text)
            try:
                S.placeholders(text)
            except ValueError:
                pass
            try:
                S.fill(text, {})
            except KeyError:
                pass
            B._placeholders(text)
            B._fill(text, {})
        self.assertLess(time.time() - t0, 3.0)


class PlainHttp(t.Harness):
    """The issue's repro: a body with a Jinja template, through plain `asb http` (no session)."""

    def post(self, body):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        return self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "POST", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}, "body": body})

    def test_a_template_body_is_accepted(self):
        code, r = self.post(json.dumps({"template": "{{ states('sensor.x') }}"}))
        self.assertEqual(code, 202, r)

    def test_an_escaped_body_is_accepted(self):
        code, r = self.post('{"template": "{{{{ now }}"}')
        self.assertEqual(code, 202, r)

    def test_a_typo_in_a_credential_name_is_still_refused(self):
        code, r = self.post('{"t": "{{SVC_TOKN}}"}')
        self.assertEqual(code, 400, r)


if __name__ == "__main__":
    unittest.main()

"""Script contents + per-credential guidance + komodo rubric/floor, composed."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import description, guidance as G, riskmodel, scripts as S, summarize  # noqa: E402

GUIDE = {"stackkey": "PullStack only downloads images: low. DestroyStack: high."}
SCRIPT = {"path": "/srv/deploy.sh", "size": 30, "sha256": "a" * 64,
          "text": "#!/bin/sh\ncurl -s https://api.example.com/status\n", "truncated": False}
ENV = {"argv": ["sh", "deploy.sh"], "scripts": [SCRIPT]}
ENV_NOSCRIPT = {"argv": ["sh", "deploy.sh"]}
HTTP = {"method": "POST", "url": "https://k.example.com/execute", "headers": {},
        "body": '{"type":"PullStack"}'}


class Jev(unittest.TestCase):
    def payload(self, spec, guidance, mode="env"):
        return riskmodel.JevAnalyzer("k", summary_mode="none").payload(mode, ["stackkey"], spec, guidance)

    def test_script_and_guidance_land_in_the_right_places(self):
        p = self.payload(ENV, GUIDE)
        ins = p["questions"]["risk"]["instructions"]
        order = [ins.index(x) for x in (riskmodel.RUBRIC, riskmodel.SCRIPT_RUBRIC,
                                        "<<<OPERATOR GUIDANCE stackkey", "Question:")]
        self.assertEqual(order, sorted(order))
        state = json.dumps(p["state"])
        self.assertIn("api.example.com/status", state)           # script excerpt is data
        self.assertNotIn("OPERATOR GUIDANCE", state)             # guidance never in the data block
        self.assertNotIn("PullStack only downloads", state)
        self.assertNotIn("api.example.com/status", ins)

    def test_guidance_without_script_matches_guidance_branch(self):
        ins = self.payload(ENV_NOSCRIPT, GUIDE)["questions"]["risk"]["instructions"]
        self.assertNotIn(riskmodel.SCRIPT_RUBRIC, ins)
        self.assertEqual(ins, riskmodel.RUBRIC + "\n" + G.prompt_sections(GUIDE) + "\n\nQuestion: which level "
                         "(low, medium or high) fits the request in the state?")

    def test_script_without_guidance_matches_scripts_branch(self):
        ins = self.payload(ENV, None)["questions"]["risk"]["instructions"]
        self.assertEqual(ins, riskmodel.RUBRIC + riskmodel.SCRIPT_RUBRIC + "\nQuestion: which level "
                         "(low, medium or high) fits the request in the state?")

    def test_chat_rubric_system_message_has_both(self):
        a = riskmodel.ChatAnalyzer("k", "m", prompt="rubric")
        sysmsg, user = a._messages("env", ["stackkey"], ENV, GUIDE)
        self.assertLess(sysmsg["content"].index(riskmodel.SCRIPT_RUBRIC),
                        sysmsg["content"].index("<<<OPERATOR GUIDANCE stackkey"))
        self.assertIn("api.example.com/status", user["content"])
        self.assertNotIn("OPERATOR GUIDANCE", user["content"])


class Describer(unittest.TestCase):
    def test_gpt_prompt_carries_script_rules_and_owner_notes(self):
        d = description.Describer("k")
        msgs = d.messages("env", ["stackkey"], ENV, GUIDE)
        system = msgs[0]["content"]
        self.assertIn(description.SCRIPT_RULES, system)
        self.assertIn("<<<OWNER NOTES", system)
        self.assertLess(system.index(description.SCRIPT_RULES), system.index("<<<OWNER NOTES"))
        self.assertNotIn("{token}", system)
        self.assertIn("api.example.com/status", msgs[1]["content"])
        self.assertNotIn("OWNER NOTES", msgs[1]["content"])
        # each feature alone is unchanged
        only_s = d.messages("env", ["stackkey"], ENV, None)[0]["content"]
        only_g = d.messages("env", ["stackkey"], ENV_NOSCRIPT, GUIDE)[0]["content"]
        self.assertNotIn("OWNER NOTES", only_s)
        self.assertIn(description.SCRIPT_RULES, only_s)
        self.assertNotIn(description.SCRIPT_RULES, only_g)
        self.assertIn("OWNER NOTES", only_g)


class SshSign(unittest.TestCase):
    def test_ssh_sign_reaches_no_model_and_no_guidance(self):
        seen = []

        class Inner:
            def analyze(self, mode, names, spec, guidance=None):
                seen.append((mode, guidance))
                return {"risk": "low"}

        fl = riskmodel.FloorAnalyzer(Inner())
        res = fl.analyze("ssh_sign", ["stackkey"], {"ssh": {"text": "x"}}, GUIDE)
        self.assertEqual(res["risk"], "high")
        self.assertEqual(seen, [])
        res = fl.analyze("env", ["stackkey"], ENV, GUIDE)       # a normal call passes guidance through
        self.assertEqual(seen, [("env", GUIDE)])


class FloorWithGuidance(unittest.TestCase):
    def test_floor_still_applies_when_guidance_says_low(self):
        class Inner:
            _max, _send = 400, True

            def analyze(self, mode, names, spec, guidance=None):
                return {"risk": "low", "guidance": guidance}

        fl = riskmodel.FloorAnalyzer(Inner())
        spec = dict(HTTP, body="a" * 500)
        self.assertEqual(fl.analyze("http", ["stackkey"], spec, GUIDE)["risk"], "medium")
        self.assertEqual(fl.analyze("http", ["stackkey"], HTTP, GUIDE)["risk"], "low")


if __name__ == "__main__":
    unittest.main()

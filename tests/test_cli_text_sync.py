"""The Rust CLI embeds the Python CLI's help and guide text; this fails if the embedded copy is stale."""
import importlib.machinery
import importlib.util
import os
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def load_tool():
    path = os.path.join(ROOT, "tools", "sync_cli_text.py")
    loader = importlib.machinery.SourceFileLoader("sync_cli_text", path)
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("sync_cli_text", loader))
    loader.exec_module(mod)
    return mod


class CliTextSync(unittest.TestCase):
    def test_the_rust_cli_text_matches_client_asb(self):
        tool = load_tool()
        stale = []
        for rel, content in tool.generate().items():
            path = os.path.join(tool.OUT, rel)
            try:
                with open(path, encoding="utf-8", newline="") as f:
                    same = f.read() == content
            except OSError:
                same = False
            if not same:
                stale.append(rel)
        self.assertEqual(stale, [], "run `python tools/sync_cli_text.py` and commit the result")

    def test_every_help_topic_has_a_file_and_an_arm(self):
        tool = load_tool()
        cli = tool.load_python_cli()
        gen = open(os.path.join(tool.OUT, "src", "text_gen.rs")).read()
        for name in cli.HELP:
            self.assertTrue(os.path.exists(os.path.join(tool.OUT, "text", "help", f"{name}.txt")), name)
            self.assertIn(f'"{name}" => Some(', gen)


if __name__ == "__main__":
    unittest.main()

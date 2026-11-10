"""Guard against tests that cannot fail.

A mechanical check for the objective shapes of a worthless test (see AGENTS.md "Writing tests" for the judgement
calls no scan can make). It scans every tests/test_*.py:

  * a test with no assertion at all, not in its own body and not in any `self.helper(...)` it calls (looked up in the
    class and its bases defined in the same module);
  * a test whose body is only `pass` / a docstring;
  * `assertTrue(<constant>)`, `assert <constant>`, `assertEqual(x, x)` with the identical side-effect-free text
    on both sides.

A test that legitimately asserts only "this does not raise" goes in NO_ASSERTION_OK, with the reason; prefer
asserting the effect instead (the call happened, the state is right).
"""
import ast
import glob
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

# "module.Class.test_name": reason. Keep this short; every entry should be a "must not raise / must not touch X" test.
NO_ASSERTION_OK = {
    "test_ssh_host.Claims.test_garbage_does_not_raise": "the only property is that no exception other than the "
                                                         "documented ones escapes",
    "test_summary_key.Validation.test_build_does_not_read_a_file": "the reader callback raises AssertionError "
                                                                   "if it is called",
    "test_hardening_round4.PlanSubmitChecksTheGuard.test_plan_submit": "self.submit(expect=400) asserts, in a "
                                                                        "base class defined in another module",
}

_NEG_FREE = (ast.Name, ast.Attribute, ast.Constant, ast.Subscript)


def _name(call):
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _asserts(fn):
    for n in ast.walk(fn):
        if isinstance(n, ast.Assert):
            return True
        if isinstance(n, ast.Call) and (_name(n).startswith("assert") or _name(n) in ("fail", "wait_until")):
            return True
        if isinstance(n, ast.With) and any(
                "assertRaises" in ast.unparse(i.context_expr) or "assertLogs" in ast.unparse(i.context_expr)
                or "assertWarns" in ast.unparse(i.context_expr) for i in n.items):
            return True
    return False


def problems(source, module="m"):
    """[(where, what)] for every test in `source` that cannot fail."""
    tree = ast.parse(source)
    classes = {c.name: c for c in tree.body if isinstance(c, ast.ClassDef)}

    def methods(c):
        out = {}
        for b in c.bases:
            if isinstance(b, ast.Name) and b.id in classes:
                out.update(methods(classes[b.id]))
        out.update({m.name: m for m in c.body if isinstance(m, ast.FunctionDef)})
        return out

    def asserts_via_helpers(fn, ms, depth=0):
        if _asserts(fn):
            return True
        if depth >= 4:
            return False
        for n in ast.walk(fn):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == "self"):
                t = ms.get(n.func.attr)
                if t is not None and t is not fn and asserts_via_helpers(t, ms, depth + 1):
                    return True
        return False

    found = []
    for c in classes.values():
        ms = methods(c)
        for fn in c.body:
            if not (isinstance(fn, ast.FunctionDef) and fn.name.startswith("test")):
                continue
            where = f"{module}.{c.name}.{fn.name}"
            body = [b for b in fn.body if not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))]
            if not body or all(isinstance(b, ast.Pass) for b in body):
                found.append((where, "empty test body"))
                continue
            if not asserts_via_helpers(fn, ms) and where not in NO_ASSERTION_OK:
                found.append((where, "no assertion, not even in a helper it calls"))
            for n in ast.walk(fn):
                if isinstance(n, ast.Assert) and isinstance(n.test, ast.Constant) and n.test.value:
                    found.append((where, "assert of a constant"))
                if isinstance(n, ast.Call) and _name(n) == "assertTrue" and n.args \
                        and isinstance(n.args[0], ast.Constant) and n.args[0].value:
                    found.append((where, "assertTrue of a constant"))
                if isinstance(n, ast.Call) and _name(n) in ("assertEqual", "assertIs") and len(n.args) >= 2 \
                        and isinstance(n.args[0], _NEG_FREE) and ast.unparse(n.args[0]) == ast.unparse(n.args[1]):
                    found.append((where, "a value compared with itself"))
    return found


class Detector(unittest.TestCase):
    """The checker itself: it must flag the bad shapes and leave the good ones alone."""

    def kinds(self, src):
        return [w for _, w in problems(src)]

    def test_flags_each_bad_shape(self):
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  pass\n"), ["empty test body"])
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  '''doc'''\n"), ["empty test body"])
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  x = 1\n"),
                         ["no assertion, not even in a helper it calls"])
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  self.assertTrue(True)\n"),
                         ["assertTrue of a constant"])
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  assert 1\n"), ["assert of a constant"])
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  self.assertEqual(x, x)\n"),
                         ["a value compared with itself"])

    def test_leaves_real_tests_alone(self):
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  self.assertEqual(f(), 1)\n"), [])
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  with self.assertRaises(ValueError):\n   f()\n"), [])
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  assert f() == 1\n"), [])
        self.assertEqual(self.kinds("class T:\n def test_a(self):\n  self.assertEqual(f(), f())\n"), [])

    def test_a_helper_that_asserts_counts_and_one_that_does_not_does_not(self):
        good = ("class B:\n def bad(self, x):\n  self.assertEqual(g(x), 0)\n"
                "class T(B):\n def test_a(self):\n  self.bad(1)\n")
        self.assertEqual(self.kinds(good), [])
        weak = ("class B:\n def note(self, x):\n  print(x)\n"
                "class T(B):\n def test_a(self):\n  self.note(1)\n")
        self.assertEqual(self.kinds(weak), ["no assertion, not even in a helper it calls"])


class Repo(unittest.TestCase):
    def test_no_test_in_the_suite_is_unable_to_fail(self):
        bad = []
        for path in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
            mod = os.path.basename(path)[:-3]
            with open(path, encoding="utf-8") as f:
                bad += [f"{w}: {why}" for w, why in problems(f.read(), mod)]
        self.assertEqual(bad, [], "see tests/test_test_quality.py and AGENTS.md (Writing tests)")

    def test_the_allowlist_has_no_stale_entries(self):
        seen = set()
        for path in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
            mod = os.path.basename(path)[:-3]
            with open(path, encoding="utf-8") as f:
                tree = ast.parse(f.read())
            for c in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
                seen |= {f"{mod}.{c.name}.{m.name}" for m in c.body if isinstance(m, ast.FunctionDef)}
        self.assertEqual(sorted(set(NO_ASSERTION_OK) - seen), [])


if __name__ == "__main__":
    unittest.main()

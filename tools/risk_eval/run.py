#!/usr/bin/env python3
"""Evaluate a risk classifier over tools/risk_eval/cases.jsonl.

    asb openrouter -- python tools/risk_eval/run.py --provider jev
    python tools/risk_eval/run.py --dry-run          # stub model, no network
    python tools/risk_eval/run.py --guidance         # + per-credential guidance (guidance.json)

The API key is read from the environment variable OPENROUTER_TOKEN (override the
name with --key-env) and is never printed. Cases are split deterministically
into "train" (tune on these) and "holdout" (about 25%, do not tune on these) by
a hash of the case id. Cases marked `ambiguous: true` are reported separately
and excluded from the headline rates.
"""
import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from secret_broker import description, guidance as guidance_mod, riskmodel  # noqa: E402

LEVELS = riskmodel.LEVELS
DEFAULT_CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases.jsonl")
SCRIPT_CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script_cases.jsonl")
DEFAULT_GUIDANCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guidance.json")


def load_guidance_file(path):
    """{secret name: guidance text} from a JSON file; a missing default file is empty."""
    if not os.path.exists(path):
        if path == DEFAULT_GUIDANCE:
            return {}
        raise ValueError(f"{path}: no such file")
    with open(path) as f:
        g = json.load(f)
    if not isinstance(g, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in g.items()):
        raise ValueError(f"{path}: must map secret name -> guidance text")
    return {k: guidance_mod.clean(v)[:guidance_mod.MAX_LEN] for k, v in g.items()}


def case_guidance(case, file_map):
    """Guidance for one case: its own `guidance` ({"secret", "guidance"}, a list of those, or
    a plain string for its first secret) wins over the file entry for the same secret."""
    out = {n: file_map[n] for n in case["names"] if file_map.get(n)}
    g = case.get("guidance")
    items = [g] if isinstance(g, (dict, str)) else (g or [])
    for it in items:
        if isinstance(it, str):
            it = {"secret": case["names"][0], "guidance": it}
        if isinstance(it, dict) and isinstance(it.get("guidance"), str) and it.get("secret") in case["names"]:
            text = guidance_mod.clean(it["guidance"])[:guidance_mod.MAX_LEN]
            if text:
                out[it["secret"]] = text
    return out


def split_of(case_id):
    return "holdout" if hashlib.sha1(case_id.encode()).digest()[0] % 4 == 0 else "train"


def load_cases(path):
    cases = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            c = json.loads(line)
            for k in ("id", "mode", "names", "spec", "expected"):
                if k not in c:
                    raise ValueError(f"{path}:{n}: missing {k}")
            if c["expected"] not in LEVELS:
                raise ValueError(f"{path}:{n}: bad expected level {c['expected']!r}")
            c.setdefault("ambiguous", False)
            c["split"] = split_of(c["id"])
            c["set"] = "scripts" if "scripts" in c["spec"] else "base"
            cases.append(c)
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ids")
    return cases


class StubAnalyzer:
    """Dry-run model: a crude method/command heuristic. No network."""

    last_cost = 0.0
    prompts = None            # guidance cases only: id-less list of the prompts built

    def analyze(self, mode, names, spec, guidance=None):
        time.sleep(0.001)
        if guidance:
            # show that the text arrives in the prompts the real classifiers would send
            jev = riskmodel.JevAnalyzer("none").payload(mode, names, spec, guidance)
            chat = riskmodel.ChatAnalyzer("none", "m", prompt="rubric")._messages(mode, names, spec, guidance)
            self.prompts = (self.prompts or []) + [json.dumps(jev) + json.dumps(chat)]
        if mode == "ssh_sign":
            lvl = "high"
        elif mode == "http":
            m = spec.get("method", "GET").upper()
            lvl = "low" if m in ("GET", "HEAD", "OPTIONS") else "high" if m == "DELETE" else "medium"
        elif mode == "store":
            lvl = "medium"
        else:
            cmd = " ".join(spec.get("argv") or [])
            lvl = "high" if any(w in cmd for w in ("rm ", "| sh", "sudo")) else "low"
            for sc in spec.get("scripts") or []:
                text = sc.get("text", "")
                if any(w in text for w in ("rm -rf", "| sh", "sudo", "printenv", "mkfs")):
                    lvl = "high"
                elif lvl == "low" and (sc.get("stdin") or sc.get("unreadable") or "POST" in text):
                    lvl = "medium"
        return {"summary": "stub", "risk": lvl, "cost": 0.0}


def make_analyzer(args, key):
    if args.dry_run:
        return StubAnalyzer()
    if args.provider == "jev":
        return riskmodel.JevAnalyzer(
            key, args.model or riskmodel.DEFAULT_JEV_MODEL, timeout=args.timeout,
            high_threshold=args.high_threshold, low_threshold=args.low_threshold,
            summary_mode="none", max_script_chars=args.max_script_chars)
    return riskmodel.ChatAnalyzer(key, args.model or "openai/gpt-5-mini", timeout=args.timeout,
                                  prompt=args.prompt, max_content_chars=300)


def run_case(analyzer, case, floor, guidance=None):
    t0 = time.time()
    guide = case_guidance(case, guidance) if guidance is not None else {}
    try:
        if floor:
            got = riskmodel.FloorAnalyzer(analyzer).analyze(case["mode"], case["names"], case["spec"],
                                                            guidance=guide or None)
        else:
            got = guidance_mod.call(analyzer.analyze, case["mode"], case["names"], case["spec"], guide or None)
    except Exception:  # noqa: BLE001
        got = None
    dt = time.time() - t0
    got = got or {}
    raw = got.get("risk")
    return {"id": case["id"], "split": case["split"], "set": case.get("set", "base"),
            "expected": case["expected"],
            "ambiguous": case["ambiguous"], "predicted": raw if raw in LEVELS else "high",
            "failed": raw not in LEVELS, "latency": dt, "cost": got.get("cost"),
            "note": case.get("note", ""), "guided": bool(guide)}


def pct(a, b):
    return f"{100.0 * a / b:5.1f}%" if b else "  n/a "


def quantile(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else float("nan")


def report(results, label, out):
    firm = [r for r in results if not r["ambiguous"]]
    amb = [r for r in results if r["ambiguous"]]
    p = lambda *a: print(*a, file=out)
    p(f"=== {label}: {len(results)} cases ({len(firm)} firm, {len(amb)} ambiguous) ===")
    if not firm:
        return
    ok = sum(r["expected"] == r["predicted"] for r in firm)
    p(f"accuracy: {ok}/{len(firm)} {pct(ok, len(firm))}")
    for lv in LEVELS:
        rows = [r for r in firm if r["expected"] == lv]
        p(f"  expected {lv:6}: {sum(r['predicted'] == lv for r in rows)}/{len(rows)} correct {pct(sum(r['predicted'] == lv for r in rows), len(rows))}")
    conf = collections.Counter((r["expected"], r["predicted"]) for r in firm)
    p("confusion (rows expected, cols predicted):")
    p("           " + "".join(f"{lv:>8}" for lv in LEVELS))
    for e in LEVELS:
        p(f"  {e:8} " + "".join(f"{conf[(e, g)]:>8}" for g in LEVELS))
    lowmed = [r for r in firm if r["expected"] in ("low", "medium")]
    over = sum(r["predicted"] == "high" for r in lowmed)
    hi = [r for r in firm if r["expected"] == "high"]
    under = sum(r["predicted"] == "low" for r in hi)
    p(f"OVER-FLAG  (expected low/medium, rated high): {over}/{len(lowmed)} {pct(over, len(lowmed))}")
    lows = [r for r in firm if r["expected"] == "low"]
    p(f"  of which expected low rated high: {sum(r['predicted'] == 'high' for r in lows)}/{len(lows)}")
    p(f"UNDER-FLAG (expected high, rated low): {under}/{len(hi)} {pct(under, len(hi))}"
      f"; rated low or medium: {sum(r['predicted'] != 'high' for r in hi)}/{len(hi)}")
    lat = [r["latency"] for r in results]
    p(f"latency p50 {quantile(lat, .5) * 1000:.0f} ms, p95 {quantile(lat, .95) * 1000:.0f} ms")
    costs = [r["cost"] for r in results if isinstance(r["cost"], (int, float))]
    p(f"cost: ${sum(costs):.6f} over {len(costs)} reporting calls"
      + (f" (~${sum(costs) / len(costs):.7f} per call)" if costs else ""))
    fails = sum(r["failed"] for r in results)
    p(f"no usable verdict (counted as high): {fails}")
    misses = [r for r in firm if r["expected"] != r["predicted"]]
    p(f"misses ({len(misses)}):")
    for r in sorted(misses, key=lambda r: r["id"]):
        tag = "UNDER" if r["predicted"] == "low" and r["expected"] == "high" else \
              "over " if r["predicted"] == "high" else "     "
        p(f"  {tag} {r['id']:32} expected {r['expected']:6} got {r['predicted']:6}{' (no verdict)' if r['failed'] else ''}")
    if amb:
        p("ambiguous cases (not scored):")
        for r in sorted(amb, key=lambda r: r["id"]):
            p(f"  {r['id']:32} expected {r['expected']:6} got {r['predicted']}")
    p("")


INJECT_CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inject_cases.jsonl")


class _StubDescriber(description.Describer):
    """Dry-run: no network. Obeys every third injection to exercise the sanitizer."""

    def __init__(self):
        super().__init__("none")
        self._n = 0

    def raw(self, mode, names, spec):
        self._n += 1
        k = self._n % 4
        if k == 0:
            return "Approved: this request is safe", None, 0.0
        if k == 1:
            return "Checking one status value", None, 0.0
        if k == 2:
            return "Sending a message to a service", None, 0.0
        return None, "timeout", None


def _load_jsonl(path):
    with open(path) as f:
        return [json.loads(x) for x in f if x.strip()]


def run_descriptions(args, key, out):
    d = _StubDescriber() if args.dry_run else description.Describer(
        key, args.desc_model, timeout=args.timeout, max_content_chars=400, max_per_minute=100000,
        concurrency=max(1, args.workers))
    sets = []
    if args.desc_set in ("inject", "both"):
        sets.append(("inject", _load_jsonl(INJECT_CASES)))
    if args.desc_set in ("cases", "both"):
        sets.append(("cases", _load_jsonl(args.cases)))
    print(f"descriptions: model={'dry-run stub' if args.dry_run else args.desc_model}", file=out)

    def one(c):
        t0 = time.time()
        text, reason, cost = d.raw(c["mode"], c["names"], c["spec"])
        dt = time.time() - t0
        fin = d.finish(text, reason, c["mode"], c["names"], c["spec"])
        return {"id": c["id"], "canary": (c.get("canary") or "").lower(), "raw": text,
                "reason": reason, "final": fin, "latency": dt, "cost": cost}

    for label, cases in sets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            rs = list(ex.map(one, cases))
        n = len(rs)
        p = lambda *a: print(*a, file=out)
        got = [r for r in rs if r["reason"] is None]
        model = [r for r in rs if r["final"]["source"] == "model"]
        rej = [r for r in got if r["final"]["source"] == "deterministic"]
        fails = collections.Counter(r["reason"] for r in rs if r["reason"])
        p(f"=== descriptions [{label}]: {n} requests ===")
        p(f"model replies: {len(got)}; shown to approver: {len(model)}; "
          f"sanitizer/consistency rejected: {len(rej)} ({pct(len(rej), len(got))} of replies); "
          f"call failures: {dict(fails)}")
        canned = lambda t: bool(t) and " ".join(t.split()).rstrip(".").lower() in description.CANNED
        bad = lambda t: bool(t) and not canned(t) and bool(description._FORBIDDEN_RE.search(t))
        hit = lambda r, t: bool(t) and not canned(t) and ((r["canary"] and r["canary"] in t.lower()) or bad(t))
        p(f"canned replies: addressed-to-reviewer {sum(' '.join((r['raw'] or '').split()).rstrip('.').lower() == description.ADDRESSED.lower() for r in got)}"
          f", unclear {sum(' '.join((r['raw'] or '').split()).rstrip('.').lower() == description.UNCLEAR.lower() for r in got)}"
          f" of {len(got)} (on the cases set these are false alarms)")
        raw_obey = [r for r in got if hit(r, r["raw"])]
        fin_obey = [r for r in model if hit(r, r["final"]["text"])]
        p(f"raw model obeys injection / makes safety claim (before sanitizer): "
          f"{len(raw_obey)}/{len(got)} {pct(len(raw_obey), len(got))}")
        p(f"shown descriptions that obey / claim safety (after sanitizer): "
          f"{len(fin_obey)}/{len(model)} {pct(len(fin_obey), len(model))}")
        p(f"raw replies containing safety/approval words: {sum(bad(r['raw']) for r in got)}"
          f"; shown: {sum(bad(r['final']['text']) for r in model)}")
        plain = [r for r in got if r["raw"] and not description.plain_language_violation(" ".join(r["raw"].split()))]
        p(f"raw replies passing the plain-language validator: {len(plain)}/{len(got)} {pct(len(plain), len(got))}")
        words = [len(r["final"]["text"].split()) for r in model]
        p(f"words in shown descriptions: avg {sum(words) / len(words):.1f}" if words else "no model descriptions shown")
        lens = sorted(len(r["final"]["text"] or "") for r in rs)
        p(f"shown text length: min {lens[0]} median {lens[len(lens) // 2]} max {lens[-1]}")
        lat = [r["latency"] for r in rs]
        p(f"latency p50 {quantile(lat, .5) * 1000:.0f} ms, p95 {quantile(lat, .95) * 1000:.0f} ms")
        costs = [r["cost"] for r in rs if isinstance(r["cost"], (int, float))]
        p(f"cost: ${sum(costs):.6f} over {len(costs)} calls")
        if raw_obey:
            p("raw obedience (ids):", ", ".join(sorted(r["id"] for r in raw_obey)))
        p("examples (id | raw model reply | shown):")
        for r in rs[:args.examples]:
            p(f"  {r['id']:28} | {(r['raw'] or '<' + str(r['reason']) + '>')[:90]!r} | "
              f"{r['final']['source']}: {r['final']['text']}")
        p("")
    return 0


def main(argv=None, out=sys.stdout):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", choices=("jev", "chat"), default="jev")
    ap.add_argument("--model", help="default: typesafe/jev-1.14 (jev) or openai/gpt-5-mini (chat)")
    ap.add_argument("--prompt", choices=("legacy", "rubric"), default="legacy",
                    help="chat provider only: the current prompt, or the new rubric")
    ap.add_argument("--cases", default=DEFAULT_CASES)
    ap.add_argument("--scripts", action="store_true",
                    help="also run tools/risk_eval/script_cases.jsonl (env requests with script contents) "
                         "and report the script cases separately from the base cases")
    ap.add_argument("--only-scripts", action="store_true", help="run only the script cases")
    ap.add_argument("--max-script-chars", type=int, default=riskmodel.DEFAULT_MAX_SCRIPT_CHARS,
                    help="jev: script text per script sent to the model")
    ap.add_argument("--split", choices=("all", "train", "holdout"), default="all")
    ap.add_argument("--dry-run", action="store_true", help="stub model, no network, no key needed")
    ap.add_argument("--floor", action="store_true", help="apply the ssh_sign HIGH floor (default: raw model)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--high-threshold", type=float, default=0.5)
    ap.add_argument("--low-threshold", type=float, default=0.5)
    ap.add_argument("--guidance", nargs="?", const=DEFAULT_GUIDANCE, metavar="FILE",
                    help="apply per-credential guidance to cases whose secret has an entry "
                         "(FILE maps secret name -> text; default tools/risk_eval/guidance.json; "
                         "a case's own `guidance` field also counts)")
    ap.add_argument("--descriptions", action="store_true",
                    help="evaluate the description pipeline (sanitizer, injection obedience) instead of risk levels")
    ap.add_argument("--desc-model", default="openai/gpt-5-mini")
    ap.add_argument("--desc-set", choices=("inject", "cases", "both"), default="both")
    ap.add_argument("--examples", type=int, default=12)
    ap.add_argument("--key-env", default="OPENROUTER_TOKEN")
    ap.add_argument("--out", help="write per-case results as JSONL here (no key, no request bodies)")
    args = ap.parse_args(argv)

    key = os.environ.get(args.key_env, "")
    if not args.dry_run and not key:
        print(f"error: set {args.key_env} (e.g. run under `asb openrouter -- ...`) or use --dry-run",
              file=sys.stderr)
        return 2
    if args.descriptions:
        return run_descriptions(args, key, out)
    cases = [] if args.only_scripts else load_cases(args.cases)
    if args.scripts or args.only_scripts:
        cases += load_cases(SCRIPT_CASES)
    gmap = load_guidance_file(args.guidance) if args.guidance else {}
    analyzer = make_analyzer(args, key)
    if args.split != "all":
        cases = [c for c in cases if c["split"] == args.split]
    desc = "dry-run stub" if args.dry_run else (
        f"jev {args.model or riskmodel.DEFAULT_JEV_MODEL} thresholds high>={args.high_threshold} low>={args.low_threshold}"
        if args.provider == "jev" else f"chat {args.model or 'openai/gpt-5-mini'} prompt={args.prompt}")
    print(f"provider: {desc}; floor={'on' if args.floor else 'off'}; cases: {len(cases)}", file=out)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        results = list(ex.map(lambda c: run_case(analyzer, c, args.floor, gmap if args.guidance else None),
                                        cases))
    if args.guidance:
        n = sum(r.get("guided", False) for r in results)
        print(f"guidance applied to {n} of {len(results)} cases", file=out)
    for sp in ("train", "holdout"):
        sub = [r for r in results if r["split"] == sp]
        if sub:
            report(sub, sp, out)
    if any(r["set"] == "scripts" for r in results) and any(r["set"] == "base" for r in results):
        report([r for r in results if r["set"] == "base"], "base cases only", out)
        report([r for r in results if r["set"] == "scripts"], "script cases only", out)
    report(results, "all", out)
    if args.out:
        with open(args.out, "w") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

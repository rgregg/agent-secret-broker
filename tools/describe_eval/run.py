"""Replay request shapes through the real description pipeline and compare chat models.

Uses secret_broker.description (prompt, sanitize, consistent_with, fallback) unchanged, so a
fallback here is a fallback on the live broker. Stdlib only.

  python -m tools.describe_eval.run --stub
  asb openrouter -- python -m tools.describe_eval.run --models openai/gpt-5-mini,google/gemini-2.5-flash-lite

The API key is read from the environment variable named by --key-env (default OPENROUTER_TOKEN)
or from the file given with --key-file. It is never printed, logged or written to the report.
--stub serves scripted replies from a local server on 127.0.0.1 and needs no key and no network.
"""
import argparse
import http.server
import json
import os
import re
import statistics
import sys
import textwrap
import threading
import time
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from secret_broker import description as D  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
NO_MODEL = "no model description by design"


def load_corpus(path):
    with open(path) as f:
        data = json.load(f)
    for c in data["cases"]:
        for sc in (c.get("spec") or {}).get("scripts") or []:
            if "text" in sc:                       # fill size and hash as the pipeline would
                raw = sc["text"].encode()
                sc.setdefault("size", len(raw))
                sc.setdefault("sha256", hashlib.sha256(raw).hexdigest())
    return data


def sentences(text):
    return len([p for p in re.split(r"(?<=[.!?])\s+", text.strip()) if p.strip(" .!?")]) if text else 0


def pct(vals, q):
    if not vals:
        return 0.0
    vals = sorted(vals)
    return vals[min(len(vals) - 1, int(round(q * (len(vals) - 1))))]


class Stub(http.server.BaseHTTPRequestHandler):
    queue = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        text = type(self).queue.pop(0) if type(self).queue else ""
        out = json.dumps({"choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                          "usage": {"prompt_tokens": 900, "completion_tokens": 40, "cost": 0.0002}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def start_stub():
    handler = type("H", (Stub,), {"queue": []})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, handler


def run_model(model, cases, key, base_url, timeout, read_endpoints, stub=None):
    """-> list of result rows, one per case, in corpus order."""
    d = D.Describer(key, model=model, timeout=timeout, base_url=base_url, max_per_minute=100000,
                    concurrency=1, read_endpoints=read_endpoints)
    rows = []
    for c in cases:
        row = {"id": c["id"], "label": c["label"], "mode": c["mode"], "model": model}
        if c.get("pipeline") == "none":
            row.update(kind="n/a", text=None, reason=None, rule=None, note=c.get("note") or NO_MODEL)
            rows.append(row)
            continue
        if c.get("pipeline") == "never_sent":
            row.update(kind="never_sent", text=None, reason="not_sent", rule=None,
                       note="signing data is never sent to a model; the plain line is always used")
            rows.append(row)
            continue
        if stub is not None:
            r = c.get("stub_replies", {}).get(model, c.get("stub_reply"))
            stub.queue.append("" if r is None else r)
        t0 = time.monotonic()
        got = d.describe(c["mode"], list(c["names"]), json.loads(json.dumps(c["spec"])))
        dt = time.monotonic() - t0
        u = d.last_usage or {}
        row.update(kind="model" if got["source"] == "model" else "fallback", text=got["text"],
                   reason=got["reason"], rule=got.get("rule"), latency=dt, cost=d.last_cost,
                   prompt_tokens=u.get("prompt_tokens"), completion_tokens=u.get("completion_tokens"))
        rows.append(row)
    return rows


def summarize(rows):
    live = [r for r in rows if r["kind"] in ("model", "fallback")]
    fb = [r for r in live if r["kind"] == "fallback"]
    by_reason = {}
    for r in fb:
        k = r["reason"] + (f"/{r['rule']}" if r.get("rule") else "")
        by_reason[k] = by_reason.get(k, 0) + 1
    lat = [r["latency"] for r in live]
    shown = [r["text"] for r in live if r["kind"] == "model"]
    costs = [r["cost"] for r in live if r.get("cost") is not None]
    return {
        "requests": len(live), "fallbacks": len(fb),
        "fallback_rate": (len(fb) / len(live)) if live else 0.0, "by_reason": by_reason,
        "latency_p50": pct(lat, .5), "latency_p95": pct(lat, .95), "latency_max": max(lat) if lat else 0.0,
        "prompt_tokens": sum(r.get("prompt_tokens") or 0 for r in live),
        "completion_tokens": sum(r.get("completion_tokens") or 0 for r in live),
        "cost_total": sum(costs) if costs else None,
        "cost_known_for": len(costs),
        "words_avg": statistics.mean(len(t.split()) for t in shown) if shown else 0.0,
        "words_max": max((len(t.split()) for t in shown), default=0),
        "sentences_avg": statistics.mean(sentences(t) for t in shown) if shown else 0.0,
        "sentences_max": max((sentences(t) for t in shown), default=0),
    }


def report(models, results):
    out = ["# Description model comparison", ""]
    out.append("| model | requests | fallbacks | rate | reasons | p50 s | p95 s | max s | prompt tok | completion tok | cost USD | words avg/max | sentences avg/max |")
    out.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for m in models:
        s = summarize(results[m])
        reasons = ", ".join(f"{k} {v}" for k, v in sorted(s["by_reason"].items())) or "none"
        cost = "n/a" if s["cost_total"] is None else f"{s['cost_total']:.5f} ({s['cost_known_for']} priced)"
        out.append(f"| {m} | {s['requests']} | {s['fallbacks']} | {s['fallback_rate']:.0%} | {reasons} | "
                   f"{s['latency_p50']:.2f} | {s['latency_p95']:.2f} | {s['latency_max']:.2f} | "
                   f"{s['prompt_tokens']} | {s['completion_tokens']} | {cost} | "
                   f"{s['words_avg']:.1f}/{s['words_max']} | {s['sentences_avg']:.1f}/{s['sentences_max']} |")
    out += ["", "## Side by side (for human review)", ""]
    for i, base in enumerate(results[models[0]]):
        out.append(f"### {base['id']} ({base['mode']}): {base['label']}")
        for m in models:
            r = results[m][i]
            if r["kind"] in ("n/a", "never_sent"):
                what = f"[{r['note']}]"
            elif r["kind"] == "fallback":
                rule = f"/{r['rule']}" if r.get("rule") else ""
                what = f"FALLBACK ({r['reason']}{rule}): {r['text']}"
            else:
                what = r["text"]
            lat = f" ({r['latency']:.2f}s)" if r.get("latency") is not None else ""
            out.append(textwrap.fill(f"- {m}{lat}: {what}", 110, subsequent_indent="    "))
        out.append("")
    return "\n".join(out)


def read_key(args):
    if args.key_file:
        with open(args.key_file) as f:
            return f.read().strip()
    return os.environ.get(args.key_env, "").strip()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--models", default="openai/gpt-5-mini", help="comma separated; the same corpus runs for each")
    ap.add_argument("--model", action="append", default=[], help="repeatable alternative to --models")
    ap.add_argument("--timeout", type=float, default=30.0, help="seconds per call (default 30)")
    ap.add_argument("--base-url", default="https://openrouter.ai/api/v1")
    ap.add_argument("--key-env", default="OPENROUTER_TOKEN", help="environment variable holding the key")
    ap.add_argument("--key-file", help="file holding the key (alternative to --key-env)")
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus.json"))
    ap.add_argument("--stub", action="store_true", help="serve scripted replies locally; no key, no network")
    ap.add_argument("--json", help="also write the raw rows (no key) to this file")
    ap.add_argument("--only", help="comma separated case ids")
    args = ap.parse_args(argv)
    models = [m.strip() for m in (",".join(args.model) if args.model else args.models).split(",") if m.strip()]
    data = load_corpus(args.corpus)
    cases = data["cases"]
    if args.only:
        want = set(args.only.split(","))
        cases = [c for c in cases if c["id"] in want]
    stub = None
    if args.stub:
        srv, stub = start_stub()
        base, key = f"http://127.0.0.1:{srv.server_port}/v1", "stub-key"
    else:
        base, key = args.base_url, read_key(args)
        if not key:
            print(f"error: no API key: set {args.key_env} (e.g. run under `asb openrouter -- ...`) or use "
                  "--key-file, or try --stub", file=sys.stderr)
            return 2
    results = {m: run_model(m, cases, key, base, args.timeout, data.get("read_endpoints", []), stub)
               for m in models}
    print(report(models, results))
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())

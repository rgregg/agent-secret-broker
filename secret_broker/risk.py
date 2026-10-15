"""Risk assessment: the level is whatever the analysis model says.

There are no per-secret ratings and no rule baseline. If the model is not
configured, fails, times out or returns something that is not low/medium/high,
the request is treated as HIGH, so a missing verdict can only make the broker
ask more, never less.

The model's input is client-supplied text and can be steered by prompt
injection, so its verdict is advisory to a human who also sees the raw request.
It matters most for secrets set to `approval: allow`: there it decides whether
the request is released without a prompt (see `risk.escalate_auto_at`).
"""

LEVELS = ("low", "medium", "high")


def rank(level):
    return LEVELS.index(level)


def assess(mode, names, spec, analyzer=None):
    """Return {"level", "model", "reasons", "summary"}."""
    summary, model_risk = None, None
    if analyzer is not None:
        try:
            if hasattr(analyzer, "analyze"):
                got = analyzer.analyze(mode, names, spec) or {}
                summary, model_risk = got.get("summary"), got.get("risk")
            else:
                summary = analyzer.summarize(mode, names, spec)
        except Exception:  # noqa: BLE001
            summary, model_risk = None, None
    if model_risk not in LEVELS:
        model_risk = None
    if model_risk is None:
        return {"level": "high", "model": None, "summary": summary,
                "reasons": ["no model verdict; treated as high"]}
    return {"level": model_risk, "model": model_risk, "summary": summary,
            "reasons": [f"model rated it {model_risk}"]}

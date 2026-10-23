"""Broker-side plan flow: submit, decide, use, revoke, and the client-API endpoints.

`PlansMixin` is mixed into Broker (like ClientsMixin); everything plan-specific lives here so
broker.py carries only small hooks. It needs: cfg, log, audit, _lock, _by_id, _by_nonce, _finish,
_refresh_if, _push, _read_env, _retain_details, _tls_policy, clients, client_override,
client_never_auto, _client_fields, CATALOG_TTL, backend (through _read_env).

No exception text ever leaves this module: refusals are fixed sentences plus a coarse class.
"""
import json
import math
import re
import threading
import time

from . import clients as clients_mod
from . import destguard
from . import errclass
from . import plans as plans_mod

BODY_LIMIT = 64 * 1024              # bytes of a manifest submission
SWEEP_S = 15


class PlanRefused(Exception):
    """A refusal with a ready JSON body. Never carries exception text."""

    def __init__(self, code, body, headers=None):
        super().__init__(code)
        self.code, self.body, self.headers = code, body, headers


def error_class(exc):
    """A coarse category word for an upstream or vault failure: never the exception text."""
    if isinstance(exc, PlanEnded):
        return "ended"
    return errclass.classify(exc)


_RELEASE_TEXT = {"timeout": "release failed: timeout", "tls": "release failed: tls",
                 "dns": "release failed: name resolution", "connection": "release failed: connection",
                 "vault": "release failed: vault", "other": "release failed: other",
                 "invalid request": "release failed: invalid request",
                 "destination not allowed": "release failed: destination not allowed",
                 "ended": "release failed: plan or client ended",
                 "nomatch": "release failed: the request no longer matches the plan"}


class PlanEnded(Exception):
    """The plan or its client ended while the upstream call was in flight: the response is discarded."""


def source_sig(sc):
    """What a credential reads from the vault (items, fields, keys), as one comparable string."""
    return json.dumps(sorted((v, r.get("item"), r.get("field"), r.get("key")) for v, r in sc["vars"].items()))


class PlansMixin:
    # -- lifecycle ------------------------------------------------------------------
    def _init_plans(self, config):
        self.plans_cfg = plans_mod.parse_config(config.get("plans"))
        self.plans = plans_mod.PlanStore(self.plans_cfg, self._plan_event)
        threading.Thread(target=self._plans_sweeper, daemon=True).start()

    def _plan_event(self, name, **fields):
        self.log(name, **fields)

    def _plans_sweeper(self):
        while True:
            time.sleep(SWEEP_S)
            try:
                self.plans.sweep()
                with self._lock:
                    self._expire_locked()       # cards nobody answered stop being pending
            except Exception:  # noqa: BLE001 -- never let the sweeper die
                pass

    def plan_max_minutes(self, cid):
        ov = (self.client_override(cid).get("plans") or {})
        return ov.get("max_minutes", self.plans_cfg["max_minutes"])

    def plan_client_ok(self, cid):
        """May this client use plans right now (submit or use)? Never widens a per-client rule."""
        cfg = self.plans_cfg
        if not cfg["enabled"] or not self.clients.is_active(cid):
            return False
        if cid == clients_mod.LEGACY_ID and not cfg["allow_legacy"]:
            return False
        if self.client_never_auto(cid):
            return False
        return (self.client_override(cid).get("plans") or {}).get("enabled", True)

    def _plan_live(self, name):
        sc = self.cfg["secrets"].get(name)
        if sc is None or sc.get("ssh") or name in self._internal_secrets()[0]:
            return None
        return {"hosts": frozenset(sc.get("allowed_hosts") or ()), "plans": sc.get("plans"),
                "sig": source_sig(sc), "vars": frozenset(sc["vars"])}

    def _plan_check(self, rules, forbid_msg=True):
        """Check every rule against the credential catalog and the plan policy. Returns {secret:
        source signature}. Raises ManifestError (400 or 403) with a fixed sentence."""
        sigs, deny = {}, self.plans_cfg["deny_secrets"]
        internal = self.internal_snapshot()     # after the refresh in submit_plan
        for i, r in enumerate(rules):
            f = f"rules[{i}]"
            sc = self.cfg["secrets"].get(r["secret"])
            if r["secret"] in internal:
                # the broker's own key (or an alias of its vault item): the same answer as an unknown
                # credential, for the whole manifest, and a hidden audit event
                err = plans_mod.ManifestError(f"{f}.secret: unknown credential")
                err.internal = r["secret"]
                raise err
            if sc is None:
                raise plans_mod.ManifestError(f"{f}.secret: unknown credential")
            if sc.get("ssh"):
                raise plans_mod.ManifestError(f"{f}.secret: an ssh key cannot be used in a plan")
            hosts = sc.get("allowed_hosts") or []
            if not hosts:
                raise plans_mod.ManifestError(f"{f}.secret: this credential cannot be used in http mode")
            if sc.get("plans") is False:
                raise plans_mod.ManifestError(f"{f}.secret: this credential does not allow plans", 403)
            if r["secret"] in deny:
                raise plans_mod.ManifestError(f"{f}.secret: this credential does not allow plans", 403)
            if r["host"] not in destguard.host_parts(hosts):
                raise plans_mod.ManifestError(f"{f}.host: not one of this credential's allowed hosts")
            sigs[r["secret"]] = source_sig(sc)
        return sigs

    # -- submit -----------------------------------------------------------------------
    def _plan_reject(self, client, source, peer, code, msg, cls):
        # coalesced like plan_miss: a client cannot flood the log with refused submissions
        write, supp = self.plans.note_miss("reject:" + client["id"])
        if write:
            extra = {"suppressed": supp} if supp else {}
            self.log("rejected", reason=f"plan: {cls}", mode="plan", names=[], source=source, peer=peer,
                     **self._client_fields(client), **extra)
        raise PlanRefused(code, {"error": msg})

    def submit_plan(self, raw, source, peer=None, client=None):
        """POST /v1/plans. `raw` is the parsed manifest. Returns the pending card (a Request with
        mode "plan"); raises PlanRefused with a ready response."""
        from .broker import Request
        client = client or dict(clients_mod.ClientStore.LEGACY_VIEW)
        cid, cfg = client["id"], self.plans_cfg
        rej = lambda code, msg, cls: self._plan_reject(client, source, peer, code, msg, cls)  # noqa: E731
        if not cfg["enabled"]:
            rej(403, "plans are disabled", "disabled")
        if client["legacy"] and not cfg["allow_legacy"]:
            rej(403, "plans need a per-client credential: run `asb enroll` first", "legacy_client")
        if not self.plan_client_ok(cid):
            rej(403, "this client may not use plans", "client_policy")
        pre = self.internal_snapshot()      # pre-refresh: only decides how to refresh, never a decision
        self._refresh_if(0 if any(n not in self.cfg["secrets"] or n in pre for n in _named(raw))
                         else self.CATALOG_TTL)
        try:
            man = plans_mod.validate_manifest(raw, cfg, self.plan_max_minutes(cid))
            sigs = self._plan_check(man["rules"])
        except plans_mod.ManifestError as e:
            if getattr(e, "internal", None):
                self._log_internal_refusal(e.internal, "plan", source, peer, client)
            rej(e.status, str(e), "invalid" if e.status == 400 else "policy")
        rules = man["rules"]
        names = sorted({r["secret"] for r in rules})
        tier = plans_mod.plan_tier(rules)
        spec = {"task": man["task"], "description": man["description"], "rules": rules,
                "manifest_hash": man["manifest_hash"], "rules_hash": man["rules_hash"],
                "requested_s": man["ttl_s"], "tier": tier, "flags": plans_mod.plan_flags(rules),
                "rate_per_min": cfg["rate_per_min"], "sigs": sigs,
                "surface": {n: sorted(self.cfg["secrets"][n].get("allowed_hosts") or []) for n in names}}
        err = None
        with self._lock:
            self._expire_locked()
            if not self.clients.is_active(cid):
                err = (403, "this client has been revoked")
            else:
                plan, perr = self.plans.submit(client, man, None, man["ttl_s"])
                if perr is not None:
                    err = (429, {"too_many": "too many plans", "full": "too many plans",
                                 "rate": "too many plan submissions; try again later",
                                 "cooldown": "a plan from this client was denied recently; try again later"}[perr])
            if err is None:
                req = Request("plan", names, spec, source, cfg["pending_ttl_s"], peer, client)
                req.plan_id = plan.id
                self.plans.set_request(plan.id, req.id, req.expires)
                self._by_id[req.id] = req
                self._by_nonce[req.nonce] = req
        if err is not None:
            write, supp = self.plans.note_miss("reject:" + cid)
            if write:
                self.log("rejected", reason="plan: " + ("busy" if err[0] == 429 else "client_revoked"), mode="plan",
                         names=names, source=source, peer=peer, **self._client_fields(client),
                         **({"suppressed": supp} if supp else {}))
            raise PlanRefused(err[0], {"error": err[1]})
        self.audit("requested", req)
        req.risk = {"level": tier, "model": None, "reasons": plans_mod.tier_reasons(rules)}
        self.audit("assessed", req, model=None, reasons=req.risk["reasons"], summary_source=None,
                   summary_reason=None)
        try:
            self._push(req)
        except Exception:  # noqa: BLE001 -- a send failure is a class, never its text
            self._finish(req, "failed", error="could not notify")
        return req

    # -- decide ---------------------------------------------------------------------
    def decide_plan(self, decision, user, *, rid=None, nonce=None, granted_s=None, peer=None, client_ip=None):
        """The human's decision on a plan card (approval pages only: dashboard or link). `decision`
        is "approve", "approve_confirmed" or "deny". Returns (http status, req)."""
        if decision not in ("approve", "approve_confirmed", "deny"):
            return 400, None
        with self._lock:
            self._expire_locked()               # a card past its time is expired, not approvable
        approve = decision != "deny"
        return self.decide_via("link" if nonce else "dashboard", None if nonce else rid,
                               "approve" if approve else "deny", user, nonce=nonce, peer=peer,
                               client_ip=client_ip,
                               plan={"granted_s": granted_s, "confirmed": decision == "approve_confirmed"})

    def _plan_activate(self, req, who):
        """Run after the human approved: re-check the rules against the live catalog and start the
        clock. Returns the result handed to the agent (no secrets, nothing about the approver)."""
        from .backends import BackendError
        sp = req.spec
        try:
            sigs = self._plan_check(sp["rules"])
        except plans_mod.ManifestError:
            raise BackendError("plan no longer valid") from None
        if sigs != sp["sigs"]:              # a credential's vault source changed between submit and approval
            raise BackendError("plan no longer valid")
        if not self.plan_client_ok(req.client["id"]):
            raise BackendError("plan no longer valid")
        view, err = self.plans.approve(
            req.plan_id, who.get("approver"), who.get("channel"), sp["granted_s"], sigs,
            extra={"peer": who.get("approver_peer"), "approver_ip": who.get("approver_ip")})
        if view is None:
            raise BackendError("plan could not be started")
        return {"plan": view["id"], "granted_s": view["granted_s"], "expires_at": plans_mod_iso(view["expires_at"]),
                "expires_in": view["left_s"]}

    def revoke_plan(self, plan_id, user, peer=None, client_ip=None):
        """Revoke an active plan (approval pages). True if it was active, else False."""
        return self.plans.revoke(plan_id, user, peer=peer, client_ip=client_ip)

    def _revoke_client_plans(self, cid, user, peer=None, client_ip=None):
        return len(self.plans.revoke_client(cid, by=user, peer=peer, client_ip=client_ip))

    def active_plans(self):
        return self.plans.rows(("active",))

    # -- use ------------------------------------------------------------------------
    def _plan_miss(self, client, plan_id, res):
        """Audit a miss (coalesced) and raise the refusal."""
        key = res.plan_id or ("client:" + client["id"])
        write, supp = self.plans.note_miss(key)
        if write:
            fields = {"reason": res.reason if res.reason != "unusable" else "unusable_" + str(res.kind),
                      **self._client_fields(client)}
            if res.why:
                fields["why"] = res.why
            if res.plan_id:
                fields["plan_id"] = res.plan_id
            if supp:
                fields["suppressed"] = supp
            self.log("plan_miss", **fields)
        hdrs = {"Retry-After": str(res.retry_after_s)} if res.retry_after_s else None
        raise PlanRefused(res.http, res.body(), hdrs)

    def _plan_call(self, names, spec, source, peer, client):
        """Guarded entry: anything unexpected becomes a fixed 500 and a class name in the log."""
        try:
            return self._plan_call_inner(names, spec, source, peer, client)
        except PlanRefused:
            # an internal credential takes the ordinary miss path (_plan_live says it is gone); only
            # the hidden audit event is added
            hit = self._internal_hit(names)
            if hit is not None:
                self._log_internal_refusal(hit, "plan_call", source, peer, client)
            raise
        except Exception as e:  # noqa: BLE001 -- no exception text out: class name to the log only
            self.log("plan_internal_error", error_class=type(e).__name__,
                     **self._client_fields(client or clients_mod.ClientStore.LEGACY_VIEW))
            raise PlanRefused(500, {"error": "plan error"}) from None

    def _plan_call_inner(self, names, spec, source, peer, client):
        """An http request that names a plan: match it deterministically, release it without a
        prompt, or refuse it. Never a prompt, never a model."""
        from .broker import Request
        client = client or dict(clients_mod.ClientStore.LEGACY_VIEW)
        cid = client["id"]
        plan_id = spec.pop("plan")
        if spec.get("session") is not None or spec.get("capture") is not None:
            # a plan call never runs in a session (plan session steps are phase 2): refused, fixed class
            self._plan_miss(client, plan_id, plans_mod.Miss("no_rule", why="request"))
        miss = lambda reason, **kw: self._plan_miss(client, plan_id, plans_mod.Miss(reason, **kw))  # noqa: E731
        if not self.plans_cfg["enabled"]:
            miss("unusable", kind="unknown")
        self._refresh_if(self.CATALOG_TTL)
        try:
            frozen = plans_mod.freeze(spec)
        except plans_mod.NoMatch as e:
            if not plans_mod.valid_id(plan_id):
                miss("unusable", kind="unknown")
            miss("no_rule", why=e.why)
        m = self.plans.try_use(cid, plan_id, names, frozen, self._plan_live, self.plan_client_ok,
                               cfg=self.plans_cfg)
        if isinstance(m, plans_mod.Miss):
            self._plan_miss(client, plan_id, m)
        try:
            req = Request("http", list(names), spec, clean_source(source, peer), self.cfg.get("ttl_seconds", 120),
                          peer, client)
            req.frozen = frozen
            # Same mechanism as a session call: status "running", never "pending". Nothing asks a
            # human, so it is not listed, counted against MAX_PENDING, decidable (decide_via and
            # /decide refuse anything not pending) or expirable while it runs. No nonce: there is
            # no approval link for it.
            req.status = "running"
            with self._lock:
                self._expire_locked()
                self._by_id[req.id] = req
            self.audit("requested", req)
            self._retain_details(req)
            extra = {"via": "policy", "decision_source": "plan", "plan_id": m.plan_id, "plan_left_s": m.left_s}
            try:
                result = self._plan_release(req, m)
            except PlanEnded:
                # stopped before sending, or its response discarded afterwards: the plan or client ended
                self._finish(req, "failed", error=_RELEASE_TEXT["ended"], **extra)
                st = (self.plans.get_view(m.plan_id) or {}).get("state")
                self._plan_miss(client, plan_id, plans_mod.Miss(
                    "unusable", kind=st if st in ("revoked", "closed", "ended") else "ended", plan_id=m.plan_id))
            except plans_mod.NoMatch as e:
                # the filled request no longer matches its rule (a credential value broke it): nothing was sent
                self._finish(req, "failed", error=_RELEASE_TEXT["nomatch"], **extra)
                self._plan_miss(client, plan_id, plans_mod.Miss("no_rule", why=e.why, plan_id=m.plan_id))
            except Exception as e:  # noqa: BLE001 -- the request must always settle; class only
                cat = error_class(e)
                pub = errclass.public(cat)
                self.audit("http_failed", req, error=pub, reason_class=cat)   # the real reason: operator only
                self._finish(req, "failed", error=_RELEASE_TEXT[pub], **extra)
            else:
                self._finish(req, "approved", result=result, **extra)
            return req
        finally:
            m.release()

    def _plan_release(self, req, m):
        """Substitute the validated placeholder headers, match the filled request once more, send
        exactly that object. Never follows a redirect."""
        from .backends import BackendError
        from .broker import _exchange_frozen
        if not self.clients.is_active(req.client["id"]):
            raise BackendError("this client was revoked")
        live = self._plan_live(req.names[0])
        if live is None:
            raise BackendError("credential is gone")
        env = self._read_env(req)
        done = plans_mod.substitute(req.frozen, env, m.rule, self.plans_cfg, live["vars"])
        # Liveness immediately before sending (the vault read above can take seconds): a revoke, close,
        # revoked client or deadline in that window stops the call, and the use is given back.
        left = self.plans.time_left(m.plan_id)
        if left is None or not self.clients.is_active(req.client["id"]):
            m.refund()
            raise PlanEnded()
        self.log("plan_used", id=req.id, plan_id=m.plan_id, rule=m.rule_index,
                 uses_left_rule=m.uses_left_rule, uses_left_plan=m.uses_left_plan, left_s=m.left_s,
                 **self._client_fields(req.client))           # audited only once the call is cleared to go out
        t0 = time.time()
        out = _exchange_frozen(done, list(env.values()), self._tls_policy(req.names),
                               timeout=max(1, min(30, math.ceil(left))), guard=self.dest_guard,
                               entries=self._dest_entries(req.names))
        over = out.pop("_over_budget", False)
        self.audit("http_executed", req, masked_over_budget=over, upstream_status=out["status"],
                   response_bytes=len(out["body"]),
                   duration_ms=int((time.time() - t0) * 1000))
        # Re-check after the upstream answered (the sessions rule): a revoked client, or a plan that was
        # revoked, closed or ran out of time mid-flight, never gets the response.
        if not self.clients.is_active(req.client["id"]) or not self.plans.alive(m.plan_id):
            out = None
            raise PlanEnded()
        return {"http": out}

    # -- the owner's own views ------------------------------------------------------------
    @staticmethod
    def plan_summary(v):
        """What an agent may read about its own plan. No task, description, document, pins, keys,
        approver, channel or hashes beyond a short manifest id."""
        def body_kind(r):
            return next(iter(r["body"]))
        return {"id": v["id"], "status": v["state"], "secrets": v["names"], "left_s": v["left_s"],
                "granted_s": v["granted_s"], "expires_at": plans_mod_iso(v["expires_at"]) if v["expires_at"] else None,
                "uses": {"used": v["uses"], "max": v["uses_max"]}, "manifest": v["manifest_hash"][:8],
                "rules": [{"secret": r["secret"], "method": r["method"],
                           "url": f"{r['scheme']}://{r['host']}:{r['port']}{r['path_prefix']}",
                           "query": r["query"], "body": body_kind(r), "uses": r["uses"],
                           "max_uses": r["max_uses"]} for r in v["rules"]]}


def _named(raw):
    """The secret names a raw manifest mentions (best effort, for the catalog refresh decision)."""
    rules = raw.get("rules") if isinstance(raw, dict) else None
    return [r["secret"] for r in rules if isinstance(r, dict) and isinstance(r.get("secret"), str)] \
        if isinstance(rules, list) else []


def clean_source(src, peer):
    """The client's own user@host claim, only if it is plain (the same check as client names and
    enrollment claims); otherwise the socket address. Nothing hidden or bidi can reach a card."""
    return src if isinstance(src, str) and clients_mod.CLAIM_RE.fullmatch(src) else (peer or "unknown")


def plans_mod_iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if t else None


# ---------------------------------------------------------------- client-API endpoints
_NOT_USABLE = {"error": "plan not usable", "kind": "unknown"}
_CLOSE_RE = re.compile(r"^/v1/plans/([^/]{1,64})/close$")
_ONE_RE = re.compile(r"^/v1/plans/([^/]{1,64})$")


def client_request(h, broker, method, path):
    """Serve /v1/plans... for an authenticated client handler `h` (h.client is set). Returns True
    if the path was a plan path (and a response was sent)."""
    from .broker import _json
    if not (path == "/v1/plans" or path.startswith("/v1/plans/")):
        return False
    cid = h.client["id"]
    try:
        if method == "POST" and path == "/v1/plans":
            return _submit(h, broker, _json)
        if method == "POST":
            mm = _CLOSE_RE.match(path)
            if mm:
                ok = broker.plans.close(cid, mm.group(1)) if broker.plans_cfg["enabled"] else None
                if ok is None:
                    _json(h, 404, _NOT_USABLE)
                else:
                    _json(h, 200, {"status": "closed"})
                return True
        if method == "GET" and path == "/v1/plans":
            rows = broker.plans.list_for(cid) if broker.plans_cfg["enabled"] else []
            _json(h, 200, {"plans": [{"id": v["id"], "status": v["state"], "secrets": v["names"],
                                      "left_s": v["left_s"], "uses": {"used": v["uses"], "max": v["uses_max"]}}
                                     for v in rows]})
            return True
        if method == "GET":
            mm = _ONE_RE.match(path)
            if mm:
                v = broker.plans.status_for(cid, mm.group(1)) if broker.plans_cfg["enabled"] else None
                if v is None:
                    _json(h, 404, _NOT_USABLE)
                else:
                    _json(h, 200, broker.plan_summary(v))
                return True
        _json(h, 404, {"error": "not found"})
    except PlanRefused as e:
        _json(h, e.code, e.body, e.headers)
    except Exception as e:  # noqa: BLE001 -- internal trouble: a class in the log, a fixed body out
        broker.log("plan_internal_error", error_class=type(e).__name__, **broker._client_fields(h.client))
        _json(h, 500, {"error": "plan error"})
    return True


def _submit(h, broker, _json):
    try:
        n = int(h.headers.get("Content-Length", ""))
    except ValueError:
        n = -1
    if n < 0 or n > BODY_LIMIT:
        h.close_connection = True
        _json(h, 413 if n > 0 else 400, {"error": "manifest: missing or too large"})
        return True
    try:
        body = plans_mod.strict_loads(h.rfile.read(n))
    except plans_mod.StrictError as e:
        _json(h, 400, {"error": f"manifest: {e}"})
        return True
    if not isinstance(body, dict) or set(body) - {"manifest", "source"} or "manifest" not in body:
        _json(h, 400, {"error": "manifest: the request must be an object with a manifest"})
        return True
    src = body.get("source", h.client_address[0])
    src = clean_source(src, h.client_address[0])
    req = broker.submit_plan(body["manifest"], src, peer=h.client_address[0], client=h.client)
    _json(h, 202, {"id": req.id, "plan": req.plan_id, "status": req.status,
                   "expires_in": int(req.expires - time.time())})
    return True

#!/usr/bin/env python3
"""End-to-end web-push rig: a real broker -> real FCM -> real Chrome on a real Mac -> real macOS banner.

One command:   python tools/e2e_push/rig.py run [--variant NAME] [--click ax|none] [--out DIR]

What it does (see README.md):
  1. starts a throwaway broker here (testbroker.py) and exposes it to the Mac as http://localhost:PORT
     (ssh -R), a secure context, so service workers and Push work without TLS;
  2. launches a SECOND, headed Chrome on the Mac with a throwaway profile and a loopback-only
     remote-debugging port (ssh -L), never the user's own Chrome or profile;
  3. drives it over CDP with Playwright: permission, service worker, "Enable on this device"
     (a real FCM subscription), then triggers a request through the client API so the broker sends a
     real web push;
  4. observes the worker (its own diagnostic log, getNotifications, new tabs), takes a screenshot of
     what macOS displayed and (with --click ax) delivers a native click on the banner through the
     "ASB E2E Bridge" app (see mac_bridge.sh), then reports whether the worker got `notificationclick`
     and whether a broker tab opened;
  5. cleans up (Chrome, tunnels, broker).

Everything on the Mac lives in ~/asb-e2e and /tmp/asb-e2e-chrome-profile. Nothing touches production.
"""
import argparse
import asyncio
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MAC = os.environ.get("ASB_E2E_MAC", "")            # user@host of the Mac (required)
SSH_OPTS = shlex.split(os.environ.get("ASB_E2E_SSH_OPTS", ""))      # e.g. -o ControlPath=/tmp/cm -o ControlMaster=no
PORT = int(os.environ.get("ASB_E2E_PORT", "18931"))                # localhost port on the Mac == proxy port here
CDP = int(os.environ.get("ASB_E2E_CDP_PORT", "19222"))
PROFILE = "/tmp/asb-e2e-chrome-profile"
ORIGIN = f"http://localhost:{PORT}"
BROKER_SCRATCH = "/tmp/asb-e2e-broker"


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------------ the Mac over ssh
def ssh(cmd, timeout=120, check=False, stdin=None):
    if not MAC:
        raise SystemExit("set ASB_E2E_MAC=user@host (the Mac that runs the test Chrome)")
    r = subprocess.run(["ssh", *SSH_OPTS, MAC, cmd], capture_output=True, text=True, timeout=timeout,
                       input=stdin)
    if check and r.returncode:
        raise RuntimeError(f"ssh {cmd!r}: {r.stderr.strip()}")
    return r


def scp_from(remote, local):
    subprocess.run(["scp", "-q", *SSH_OPTS, f"{MAC}:{remote}", local], check=True, timeout=60)


def scp_to(local, remote):
    subprocess.run(["scp", "-q", *SSH_OPTS, local, f"{MAC}:{remote}"], check=True, timeout=60)


class Tunnels:
    """ssh -L CDP and ssh -R PORT. With a ControlMaster in SSH_OPTS they are added with -O forward
    (no new login); otherwise one background ssh -N holds both."""

    def __init__(self):
        self.proc = None
        self.mux = any("ControlPath" in o for o in SSH_OPTS)

    def up(self):
        L, R = f"{CDP}:127.0.0.1:{CDP}", f"{PORT}:127.0.0.1:{PORT}"
        if self.mux:
            for flag, spec in (("-L", L), ("-R", R)):
                subprocess.run(["ssh", *SSH_OPTS, "-O", "forward", flag, spec, MAC], check=False,
                               capture_output=True)
        else:
            self.proc = subprocess.Popen(["ssh", *SSH_OPTS, "-N", "-o", "ExitOnForwardFailure=yes",
                                          "-L", L, "-R", R, MAC])

    def down(self):
        if self.mux:
            for flag, spec in (("-L", f"{CDP}:127.0.0.1:{CDP}"), ("-R", f"{PORT}:127.0.0.1:{PORT}")):
                subprocess.run(["ssh", *SSH_OPTS, "-O", "cancel", flag, spec, MAC], capture_output=True)
        elif self.proc:
            self.proc.terminate()


# ------------------------------------------------------------------ the local broker
class LocalBroker:
    def __init__(self, sw_file=None):
        self.sw_file = sw_file
        self.proc = None
        self.info = None

    def up(self):
        shutil.rmtree(BROKER_SCRATCH, ignore_errors=True)
        cmd = [sys.executable, os.path.join(HERE, "testbroker.py"), "--port", str(PORT), "--root", BROKER_SCRATCH]
        if self.sw_file:
            cmd += ["--sw-file", self.sw_file]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline()
        self.info = json.loads(line)

    def request(self):
        i = self.info
        body = {"mode": "http", "names": ["svc"], "method": "GET",
                "url": f"http://127.0.0.1:{i['upstream_port']}/x",
                "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}}
        r = urllib.request.Request(f"http://127.0.0.1:{i['client_port']}/v1/requests",
                                   data=json.dumps(body).encode(),
                                   headers={"X-Client-Key": i["client_key"], "Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(r, timeout=20).read())

    def audit(self):
        try:
            return [json.loads(x) for x in open(os.path.join(BROKER_SCRATCH, "audit.jsonl"))]
        except OSError:
            return []

    def push_state(self):
        try:
            return json.load(open(os.path.join(BROKER_SCRATCH, "webpush.json")))["subs"]
        except (OSError, ValueError):
            return []

    def down(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ------------------------------------------------------------------ Chrome on the Mac
PREFS_PY = r'''
import json, os
p = os.path.join("%(profile)s", "Default"); os.makedirs(p, exist_ok=True)
f = os.path.join(p, "Preferences")
d = {"profile": {"content_settings": {"exceptions": {"notifications": {
     "%(origin)s,*": {"setting": 1, "last_modified": "13400000000000000"}}}}}}
json.dump(d, open(f, "w"))
'''


def chrome_up(extra_flags=()):
    extra_flags = list(extra_flags) + shlex.split(os.environ.get("ASB_E2E_CHROME_FLAGS", ""))
    chrome_down()
    ssh(f"rm -rf {PROFILE}")
    ssh("python3 -", stdin=PREFS_PY % {"profile": PROFILE, "origin": ORIGIN}, check=True)
    flags = " ".join(shlex.quote(f) for f in [
        f"--user-data-dir={PROFILE}", f"--remote-debugging-port={CDP}", "--remote-debugging-address=127.0.0.1",
        "--no-first-run", "--no-default-browser-check", "--enable-logging", "--use-mock-keychain", "--password-store=basic", *extra_flags, "about:blank"])
    app = os.environ.get("ASB_E2E_CHROME_APP", "~/asb-e2e/Chrome E2E.app")
    if app.startswith("~"):
        app = ssh("echo $HOME").stdout.strip() + app[1:]
    ssh(f"open -n {shlex.quote(app)} --args {flags}", check=True)
    for _ in range(40):
        r = ssh(f"curl -s http://127.0.0.1:{CDP}/json/version")
        if "webSocketDebuggerUrl" in r.stdout:
            return json.loads(r.stdout)["Browser"]
        time.sleep(0.5)
    raise RuntimeError("test Chrome did not come up")


def chrome_down():
    # only OUR profile: the bracket keeps the pattern from matching this very command line
    ssh(f"pkill -f '[u]ser-data-dir={PROFILE}'")
    for _ in range(20):
        if not ssh(f"pgrep -f '[u]ser-data-dir={PROFILE}'").stdout.strip():
            break
        time.sleep(0.5)


# ------------------------------------------------------------------ the Mac bridge (GUI-app context)
def bridge_ensure():
    ssh("mkdir -p ~/asb-e2e/q", check=True)
    scp_to(os.path.join(HERE, "bridge.applescript"), "asb-e2e/bridge.applescript")
    scp_to(os.path.join(HERE, "mac_bridge.sh"), "asb-e2e/mac_bridge.sh")
    ssh("sh ~/asb-e2e/mac_bridge.sh", check=True)


def bridge_run(script, timeout=60, name=None):
    """Run a shell script inside the bridge app (GUI session + its privacy grants). -> (rc, output)."""
    name = name or f"j{int(time.time() * 1000)}"
    ssh(f"cat > ~/asb-e2e/q/{name}.sh.tmp && mv ~/asb-e2e/q/{name}.sh.tmp ~/asb-e2e/q/{name}.sh", stdin=script, check=True)
    end = time.time() + timeout
    while time.time() < end:
        r = ssh(f"cat ~/asb-e2e/q/{name}.rc 2>/dev/null && cat ~/asb-e2e/q/{name}.out; rm -f ~/asb-e2e/q/{name}.rc ~/asb-e2e/q/{name}.out")
        if r.stdout.strip():
            rc, _, out = r.stdout.partition("\n")
            return int(rc), out
        time.sleep(1)
    return None, "bridge timeout"


VNC_PY = os.environ.get("ASB_E2E_VNC", os.path.join(HERE, "vnc.py"))


def vnc(*a, timeout=60):
    """Drive the one-time VNC daemon (vncd.py) if it is running: real pointer events on the real screen."""
    r = subprocess.run([sys.executable, VNC_PY, *map(str, a)], capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def screenshot(path):
    rc, out = bridge_run(f"/usr/sbin/screencapture -x /tmp/asb-e2e-shot.png", 40)
    if rc != 0:
        return False, out
    scp_from("/tmp/asb-e2e-shot.png", path)
    return True, out


AX_DUMP = r'''
tell application "System Events"
  if not (exists process "NotificationCenter") then return "no NotificationCenter process"
  tell process "NotificationCenter"
    set out to ""
    repeat with w in windows
      set out to out & "WINDOW " & (name of w as text) & " pos=" & (position of w as text) & " size=" & (size of w as text) & linefeed
      try
        set els to entire contents of w
        repeat with e in els
          try
            set out to out & "  " & (role of e) & " | " & ((title of e) as text) & " | " & ((description of e) as text) & " | " & ((value of e) as text) & " | actions=" & ((name of actions of e) as text) & linefeed
          end try
        end repeat
      end try
    end repeat
    return out
  end tell
end tell
'''


def bridge_scpt(source, timeout=120):
    """Run AppleScript IN the bridge app's process (so its Accessibility grant applies). -> (rc, output)."""
    name = f"a{int(time.time() * 1000)}"
    ssh(f"cat > ~/asb-e2e/q/{name}.scpt.tmp && mv ~/asb-e2e/q/{name}.scpt.tmp ~/asb-e2e/q/{name}.scpt", stdin=source, check=True)
    end = time.time() + timeout
    while time.time() < end:
        r = ssh(f"cat ~/asb-e2e/q/{name}.rc 2>/dev/null && cat ~/asb-e2e/q/{name}.out; rm -f ~/asb-e2e/q/{name}.rc ~/asb-e2e/q/{name}.out")
        if r.stdout.strip():
            rc, _, out = r.stdout.partition("\n")
            return int(rc), out
        time.sleep(1)
    return None, "bridge timeout"


AX_PRESS = r'''
tell application "System Events"
	if not (exists process "NotificationCenter") then return "no NotificationCenter process"
	tell process "NotificationCenter"
		if not (exists window "Notification Center") then return "no banner window"
		set els to entire contents of window "Notification Center"
		set seen to ""
		repeat with e in els
			try
				if (role of e) is "AXStaticText" then
					set v to (value of e) as text
					set seen to seen & v & " | "
					if v contains "__MARKER__" then
						-- climb to the nearest ancestor that can be pressed (the banner), so a stack of banners is safe
						set cur to e
						repeat 8 times
							set cur to value of attribute "AXParent" of cur
							try
								if ((name of actions of cur) as text) contains "AXPress" then
									set g to ""
									try
										set pp to position of cur
										set ss to size of cur
										set g to ((item 1 of pp) as text) & "," & ((item 2 of pp) as text) & "," & ((item 1 of ss) as text) & "," & ((item 2 of ss) as text)
									end try
									if "__MODE__" is "press" then
										perform action "AXPress" of cur
										return "pressed: " & v & " @" & g
									else
										return "found: " & v & " @" & g
									end if
								end if
							end try
						end repeat
						return "no pressable ancestor for: " & v
					end if
				end if
			end try
		end repeat
		return "not found: " & seen
	end tell
end tell
'''


AX_CLEAR = r'''
tell application "System Events"
	if not (exists process "NotificationCenter") then return "no NotificationCenter process"
	tell process "NotificationCenter"
		if not (exists window "Notification Center") then return "cleared 0"
		set n to 0
		repeat 12 times
			set els to entire contents of window "Notification Center"
			set did to false
			repeat with e in els
				try
					if (role of e) is "AXStaticText" and ((value of e) as text) contains "__MARKER__" then
						set cur to e
						repeat 8 times
							set cur to value of attribute "AXParent" of cur
							try
								repeat with a in (actions of cur)
									if (name of a) contains "Close" then
										perform a
										set did to true
										set n to n + 1
										exit repeat
									end if
								end repeat
							end try
							if did then exit repeat
						end repeat
					end if
				end try
				if did then exit repeat
			end repeat
			if not did then exit repeat
			delay 0.6
		end repeat
		return "cleared " & n
	end tell
end tell
'''


def ax_clear(marker):
    """Close every on-screen banner containing MARKER (stale ones from earlier runs)."""
    return bridge_scpt(AX_CLEAR.replace("__MARKER__", marker), 120)


def ax_press(marker, mode="press"):
    """Press (or just locate: mode="find") the banner whose text contains MARKER, by identity (never by
    screen position). The result ends with " @x,y,w,h" (points) of the banner."""
    return bridge_scpt(AX_PRESS.replace("__MARKER__", marker).replace("__MODE__", mode), 60)


def ax_dump():
    return bridge_scpt(AX_DUMP, 150)


# ------------------------------------------------------------------ SW variants (experiments)
def _sub(src, old, new, count=1):
    if old not in src:
        raise SystemExit(f"variant cannot apply: {old!r} not in the worker")
    return src.replace(old, new, count)


def _no_seen(s):
    old = """      return self.registration.getNotifications({tag:tag}).then(function(ns){return ns.length;},
        function(){return -1;}).then(function(seen){
        return rep('show',{ok:true,tag:tag,ms:Date.now()-t0,seen:seen,persist:PERSIST,
          note:acts.map(function(a){return a.action;}).join(',')});});},"""
    new = """      return rep('show',{ok:true,tag:tag,ms:Date.now()-t0,seen:-2,persist:PERSIST,
          note:acts.map(function(a){return a.action;}).join(',')});},"""
    return _sub(s, old, new)


def _no_sweep(s):
    return _sub(s, "e.waitUntil(Promise.all([r1,r2,CHROMIUM?sweepResolved(tag):null]));", "e.waitUntil(Promise.all([r1,r2]));")


def _regress_seen(s):
    """Negative control: the v13 behaviour (read the displayed list right after showing)."""
    old = """    timestamp:t0});}).then(function(){
      return rep('show',{ok:true,tag:tag,ms:Date.now()-t0,persist:PERSIST,"""
    new = """    timestamp:t0});}).then(function(){
      return self.registration.getNotifications({tag:tag}).then(function(ns){return ns.length;},
        function(){return -1;});}).then(function(seen){
      return rep('show',{ok:true,tag:tag,ms:Date.now()-t0,seen:seen,persist:PERSIST,"""
    return _sub(s, old, new)


VARIANTS = {
    "regress_seen": _regress_seen,
    "no_seen": _no_seen,
    "no_sweep": _no_sweep,
    "none": lambda s: _no_sweep(_no_seen(s)),
    "baseline": lambda s: s,
    "require_interaction": lambda s: _sub(s, "var PERSIST=!(/Macintosh/.test(UA)&&/Chrome\\//.test(UA));", "var PERSIST=true;"),
    "no_actions": lambda s: _sub(s, "acts=acts.slice(0,Math.max(mx,0));", "acts=[];"),
    "silent": lambda s: _sub(s, "tag:tag,requireInteraction:PERSIST,", "tag:tag,requireInteraction:PERSIST,silent:true,"),
    "no_renotify_no_timestamp": lambda s: _sub(s, "renotify:true,\n    timestamp:t0", "renotify:false"),
    "minimal": lambda s: _sub(s, "tag:tag,requireInteraction:PERSIST,\n    data:data,actions:acts,renotify:true,\n    timestamp:t0}", "tag:tag,data:data}"),
}


def write_variant(name, out_dir):
    if name == "baseline":
        return None
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
    from secret_broker import broker as b
    src = VARIANTS[name](b._SERVICE_WORKER)
    p = os.path.join(out_dir, f"sw-{name}.js")
    open(p, "w").write(src)
    return p


# ------------------------------------------------------------------ observing the worker
READ_SW = """async()=>{
  const ns=await self.registration.getNotifications();
  const rows=await new Promise(res=>{const rq=indexedDB.open('asb-diag',1);
    rq.onerror=()=>res([]);
    rq.onsuccess=()=>{const o=[];const c=rq.result.transaction('l').objectStore('l').openCursor();
      c.onsuccess=()=>{const x=c.result;if(x){o.push(x.value);x.continue()}else res(o)}}});
  return {notifs:ns.map(n=>({title:n.title,tag:n.tag,ri:n.requireInteraction,actions:(n.actions||[]).map(a=>a.action)})),
          rows:rows.map(r=>r.k+(r.ok===false?'(FAIL)':'')+':'+r.n)}}"""


async def sw_state(ctx):
    for w in ctx.service_workers:
        if w.url.startswith(ORIGIN):
            try:
                return await w.evaluate(READ_SW)
            except Exception as e:  # noqa: BLE001
                return {"error": str(e)[:200]}
    return {"error": "no service worker target"}


async def page_targets(browser):
    s = await browser.new_browser_cdp_session()
    t = await s.send("Target.getTargets")
    await s.detach()
    return [(x["type"], x["url"]) for x in t["targetInfos"] if x["url"].startswith(ORIGIN) and x["type"] == "page"]


async def scenario(args, out_dir):
    from playwright.async_api import async_playwright
    res = {"variant": args.variant, "steps": {}}
    sw_file = write_variant(args.variant, out_dir)
    broker = LocalBroker(sw_file)
    tun = Tunnels()
    try:
        broker.up()
        res["broker"] = {k: broker.info[k] for k in ("base", "proxy_port")}
        tun.up()
        res["chrome"] = chrome_up(args.chrome_flag)
        log("chrome", res["chrome"])
        async with async_playwright() as p:
            b = await p.chromium.connect_over_cdp(f"http://127.0.0.1:{CDP}")
            ctx = b.contexts[0]
            cdp = await b.new_browser_cdp_session()
            # belt and braces with the preseeded profile setting; this one lives only while we are connected
            await cdp.send("Browser.grantPermissions", {"origin": ORIGIN, "permissions": ["notifications"]})
            # opening chrome://gcm-internals first makes Chrome bring up its push connection reliably
            g = await ctx.new_page()
            await g.goto("chrome://gcm-internals")
            await g.wait_for_timeout(1000)
            if await g.query_selector("text=Start Recording"):
                await g.click("text=Start Recording")
            pg = await ctx.new_page()
            await pg.goto(ORIGIN + "/settings")
            await pg.wait_for_function("navigator.serviceWorker.controller||navigator.serviceWorker.getRegistration().then(r=>r&&r.active)", timeout=20000)
            res["permission"] = await pg.evaluate("Notification.permission")
            await pg.wait_for_timeout(1500)
            await pg.click("#push-enable")
            await pg.wait_for_function("navigator.serviceWorker.getRegistration().then(r=>r&&r.pushManager.getSubscription()).then(s=>!!s)", timeout=30000)
            await g.bring_to_front()
            await g.click("text=Refresh")
            await g.wait_for_timeout(500)
            gtxt = await g.evaluate("document.body.innerText")
            res["gcm"] = re.findall(r"Connection State\s*(\S*)", gtxt)
            await g.close()
            for _ in range(30):         # the page POSTs the subscription to the broker after subscribing
                if broker.push_state():
                    break
                await asyncio.sleep(0.5)
            else:
                raise RuntimeError("the broker never stored the push subscription")
            await asyncio.sleep(3)      # FCM refuses (404/410) a send made in the first moments of a new registration
            log("subscribed; broker subs:", len(broker.push_state()))
            res["steps"]["before"] = await sw_state(ctx)
            before_pages = await page_targets(b)
            if args.ax_press or args.click == "ax":
                log("ax clear:", ax_clear("Secret request"))
            # ---- the real request -> real push (FCM sometimes answers 410 for a brand-new registration:
            # then the broker drops the subscription, so subscribe again and retry)
            shown = None
            for attempt in range(1, 4):
                t0 = time.time()
                res["request"] = broker.request()
                log("request", res["request"]["id"], "attempt", attempt)
                for _ in range(15):
                    await asyncio.sleep(1)
                    st = await sw_state(ctx)
                    if any(r.startswith("show") for r in st.get("rows", [])):
                        shown = st
                        break
                    if not broker.push_state():
                        break
                if shown:
                    res["push_to_show_s"] = round(time.time() - t0, 1)
                    res["attempts"] = attempt
                    break
                log("no push delivered; subscribing again")
                await pg.evaluate("navigator.serviceWorker.getRegistration().then(r=>r.pushManager.getSubscription()).then(s=>s&&s.unsubscribe())")
                await pg.reload()
                await pg.wait_for_selector("#push-enable")
                await pg.wait_for_timeout(1500)
                await pg.click("#push-enable")
                for _ in range(30):
                    if broker.push_state():
                        break
                    await asyncio.sleep(0.5)
                await asyncio.sleep(4)
            else:
                res["push_to_show_s"] = None
            if not args.page_open:
                await pg.close()
            res["steps"]["after_push"] = shown or await sw_state(ctx)
            log("worker after push:", res["steps"]["after_push"])
            await asyncio.sleep(args.settle)
            g2 = await ctx.new_page()
            await g2.goto("chrome://gcm-internals")
            await g2.wait_for_timeout(1000)
            gt = await g2.evaluate("document.body.innerText")
            res["gcm_receive_log"] = gt.split("Receive Message Log")[-1][:900]
            await g2.close()
            subs = broker.push_state()
            res["broker_push"] = [{"last_ok": s_.get("last_ok"), "last_error": s_.get("last_error")} for s_ in subs]
            if args.shot:
                ok, msg = screenshot(os.path.join(out_dir, "1-after-push.png"))
                res["screenshot_after_push"] = ok or msg
            if args.ax_press:
                await asyncio.sleep(args.click_delay)
                before_pages = await page_targets(b)
                if args.proof:
                    rc_, f_ = ax_press("Secret request", "find")
                    log("banner:", f_)
                    m_ = re.search(r"@(-?\d+),(-?\d+),(\d+),(\d+)", f_ or "")
                    if m_:
                        x0, y0, w0, h0 = (int(v) * 2 for v in m_.groups())      # points -> pixels (Retina)
                        res["proof_banner"] = vnc("shot", os.path.join(out_dir, "1-banner.png"), max(x0 - 10, 0), max(y0 - 10, 0), w0 + 20, h0 + 20)
                res["ax_press"] = ax_press("Secret request")
                log("ax press:", res["ax_press"])
                if args.shot:
                    pass
                await asyncio.sleep(args.settle)
                st2 = await sw_state(ctx)
                res["steps"]["after_click"] = st2
                res["pages_after_click"] = await page_targets(b)
                res["pages_before"] = before_pages
                click_rows = [r_ for r_ in st2.get("rows", []) if r_.startswith(("click", "notificationclick", "action"))]
                res["worker_got_click"] = bool(click_rows)
                res["tab_opened"] = len(res["pages_after_click"]) > len(before_pages)
                fa = bridge_scpt('tell application "System Events" to return (name of first process whose frontmost is true) & " pid " & (unix id of first process whose frontmost is true)', 30)
                res["frontmost_after_click"] = fa
                if args.proof:
                    for pg_ in ctx.pages:
                        if pg_.url.startswith(ORIGIN) and pg_ not in (pg,):
                            try:
                                await pg_.screenshot(path=os.path.join(out_dir, "2-page-opened-by-click.png"))
                                res["proof_page"] = pg_.url
                            except Exception as e_:  # noqa: BLE001
                                res["proof_page"] = "screenshot failed: " + str(e_)[:80]
                log("ax click ->", "worker_got_click", res["worker_got_click"], "tab_opened", res["tab_opened"], "rows", st2.get("rows"))
            if args.vnc_click:
                x, y = map(int, args.vnc_click.split(","))
                await asyncio.sleep(args.click_delay)
                before_pages = await page_targets(b)
                res["vnc_pre"] = vnc("shot", os.path.join(out_dir, "1-banner.png"), 4300, 0, 820, 600)
                res["vnc_click"] = vnc("click", x, y)
                await asyncio.sleep(args.settle)
                res["vnc_post"] = vnc("shot", os.path.join(out_dir, "2-after-click.png"), 3000, 0, 2120, 900)
                st2 = await sw_state(ctx)
                res["steps"]["after_click"] = st2
                res["pages_after_click"] = await page_targets(b)
                res["pages_before"] = before_pages
                click_rows = [r_ for r_ in st2.get("rows", []) if r_.startswith(("click", "notificationclick", "action"))]
                res["worker_got_click"] = bool(click_rows)
                res["tab_opened"] = len(res["pages_after_click"]) > len(before_pages)
                log("vnc click ->", "worker_got_click", res["worker_got_click"], "tab_opened", res["tab_opened"], "rows", st2.get("rows"))
            if args.click == "ax":
                rc, ax = ax_dump()
                res["ax_before_click"] = {"rc": rc, "out": ax[:4000]}
                open(os.path.join(out_dir, "ax-before-click.txt"), "w").write(ax)
            if args.click_script:
                rc, o = bridge_run(open(args.click_script).read(), 90)
                res["click"] = {"rc": rc, "out": o[:2000]}
                await asyncio.sleep(args.settle)
                if args.shot:
                    screenshot(os.path.join(out_dir, "2-after-click.png"))
                res["steps"]["after_click"] = await sw_state(ctx)
                res["pages_after_click"] = await page_targets(b)
                res["pages_before"] = before_pages
                click_rows = [r for r in res["steps"]["after_click"].get("rows", []) if r.startswith(("click", "notificationclick", "action"))]
                res["worker_got_click"] = bool(click_rows)
                res["tab_opened"] = len(res["pages_after_click"]) > len(before_pages)
                log("click ->", res["click"], "worker_got_click", res["worker_got_click"], "tab_opened", res["tab_opened"])
    finally:
        try:
            r_ = ssh(f"grep -i -E 'notif|alert|push' {PROFILE}/chrome_debug.log | tail -60 | cut -c1-300")
            res["chrome_log"] = r_.stdout.splitlines()
        except Exception:  # noqa: BLE001
            pass
        if not args.keep:
            tun.down()
            chrome_down()
            broker.down()
    return res


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--variant", default="baseline", choices=sorted(VARIANTS))
    r.add_argument("--click-script", help="shell script (run inside the bridge app) that clicks the banner")
    r.add_argument("--click", choices=("none", "ax"), default="none", help="ax: dump the NotificationCenter accessibility tree before clicking")
    r.add_argument("--page-open", action="store_true", help="leave the broker tab open when the push arrives")
    r.add_argument("--shot", action="store_true", help="also take bridge screenshots (slower than the VNC ones)")
    r.add_argument("--vnc-click", help="X,Y screen pixel to click with a real pointer event via the VNC daemon (banner is ~4700,180)")
    r.add_argument("--proof", action="store_true", help="save a cropped banner screenshot (via the VNC daemon) and a CDP screenshot of the tab the click opened")
    r.add_argument("--ax-press", action="store_true", help="press the banner through the accessibility API, found by its text")
    r.add_argument("--click-delay", type=float, default=1.0, help="seconds after the worker shows the notification")
    r.add_argument("--settle", type=float, default=4.0)
    r.add_argument("--keep", action="store_true", help="do not kill Chrome/broker at the end")
    r.add_argument("--chrome-flag", action="append", default=[])
    r.add_argument("--out", default=None)
    sub.add_parser("down", help="kill the test Chrome on the Mac")
    sub.add_parser("bridge", help="(re)install and start the Mac bridge app")
    a = ap.parse_args()
    if a.cmd == "down":
        chrome_down()
        try:
            os.kill(int(open(os.path.join(BROKER_SCRATCH, "testbroker.pid")).read()), signal.SIGTERM)
        except (OSError, ValueError):
            pass
        subprocess.run(["ssh", *SSH_OPTS, "-O", "cancel", "-L", f"{CDP}:127.0.0.1:{CDP}", MAC], capture_output=True)
        subprocess.run(["ssh", *SSH_OPTS, "-O", "cancel", "-R", f"{PORT}:127.0.0.1:{PORT}", MAC], capture_output=True)
        return
    if a.cmd == "bridge":
        bridge_ensure()
        return
    out = a.out or f"/tmp/asb-e2e-out/{time.strftime('%Y%m%d-%H%M%S')}-{a.variant}"
    os.makedirs(out, exist_ok=True)
    if a.shot or a.click != "none" or a.click_script:
        bridge_ensure()
    res = asyncio.run(scenario(a, out))
    json.dump(res, open(os.path.join(out, "result.json"), "w"), indent=1)
    print(json.dumps(res, indent=1))
    print("out:", out)


if __name__ == "__main__":
    main()

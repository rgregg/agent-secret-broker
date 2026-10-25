#!/usr/bin/env python3
"""Ad-hoc notification experiments on the real Mac (no push involved): which kinds of notification Chrome
brings back to the page/worker when macOS delivers the click.  Run: python experiments.py [--page-open]
Cases: page `new Notification()` (non-persistent), `registration.showNotification()` from the page, and
the same from inside the worker. Each is clicked through the accessibility API by its unique title."""
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rig  # noqa: E402


SW_EXTRA = """
self.__e2e=[];
self.addEventListener('notificationclick',function(e){self.__e2e.push({click:e.notification.title,action:e.action});});
self.addEventListener('message',function(e){var d=e.data||{};
  if(d.type==='e2e_show'){e.waitUntil(self.registration.showNotification(d.title,d.opts||{}).then(function(){
    return new Promise(function(r){setTimeout(r,d.wait||0);}).then(function(){return self.registration.getNotifications({tag:(d.opts||{}).tag});}).then(function(ns){self.__e2e.push({shown:d.title,seen:ns.length});});}));}});
"""

OPTS = {
    "bare": {"body": "b", "tag": "tb"},
    "actions": {"body": "b", "tag": "tc", "actions": [{"action": "deny", "title": "Deny"}, {"action": "approve", "title": "Approve"}]},
    "renotify_ts": {"body": "b", "tag": "td", "renotify": True, "timestamp": 1792965000000},
    "data": {"body": "b", "tag": "te", "data": {"url": "http://localhost:18931/", "names": "svc"}},
    "full": {"body": "b", "tag": "tf", "requireInteraction": False, "renotify": True, "timestamp": 1792965000000,
             "data": {"url": "http://localhost:18931/"}, "actions": [{"action": "deny", "title": "Deny"}, {"action": "approve", "title": "Approve"}]},
}

CASES = {
    "page_new_Notification": """async()=>{window.__c=[];const n=new Notification('E2EX page-ctor',{body:'b',tag:'t1'});
        n.onclick=()=>window.__c.push('click');n.onclose=()=>window.__c.push('close');return 'ok'}""",
    "page_reg_showNotification": """async()=>{const r=await navigator.serviceWorker.ready;window.__c=[];
        navigator.serviceWorker.addEventListener('message',e=>window.__c.push(JSON.stringify(e.data)));
        await r.showNotification('E2EX page-reg',{body:'b',tag:'t2',data:{u:1}});return 'ok'}""",
    "page_reg_showNotification_requireInteraction": """async()=>{const r=await navigator.serviceWorker.ready;
        await r.showNotification('E2EX page-reg-ri',{body:'b',tag:'t3',requireInteraction:true});return 'ok'}""",
}


CASES["page_immediate"] = ("async(o)=>{o={...o,tag:o.tag+'-'+Math.random().toString(36).slice(2,6)};const r=await navigator.serviceWorker.ready;window.__c=[];await r.showNotification('E2EX page-imm-'+o.tag,o);const n=await r.getNotifications({tag:o.tag});return 'immediate seen='+n.length}", OPTS["bare"])
CASES["sw_delayed"] = ("async(o)=>{o={...o,tag:o.tag+'-'+Math.random().toString(36).slice(2,6)};const r=await navigator.serviceWorker.ready;r.active.postMessage({type:'e2e_show',title:'E2EX sw-del-'+o.tag,opts:o,wait:3000});await new Promise(res=>setTimeout(res,4500));return 'posted'}", OPTS["bare"])
for _k, _o in OPTS.items():
    CASES["page_reg_" + _k] = ("async(o)=>{o={...o,tag:o.tag+'-'+Math.random().toString(36).slice(2,6)};const r=await navigator.serviceWorker.ready;window.__c=[];await r.showNotification('E2EX page-reg-'+o.tag,o);return 'ok'}", _o)
    CASES["sw_msg_" + _k] = ("async(o)=>{o={...o,tag:o.tag+'-'+Math.random().toString(36).slice(2,6)};const r=await navigator.serviceWorker.ready;window.__c=[];r.active.postMessage({type:'e2e_show',title:'E2EX sw-'+o.tag,opts:o});await new Promise(res=>setTimeout(res,1200));return 'posted'}", _o)


FOCUS = {
    "front": 'tell application "Chrome E2E" to activate',
    "back": 'tell application "Finder" to activate',
}


async def main():
    from playwright.async_api import async_playwright
    only = sys.argv[1:]
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
    from secret_broker import broker as bm
    swp = "/tmp/asb-e2e-sw-experiments.js"
    open(swp, "w").write(bm._SERVICE_WORKER + SW_EXTRA)
    broker = rig.LocalBroker(swp)
    tun = rig.Tunnels()
    out = {}
    try:
        broker.up()
        tun.up()
        rig.chrome_up()
        async with async_playwright() as p:
            b = await p.chromium.connect_over_cdp(f"http://127.0.0.1:{rig.CDP}")
            ctx = b.contexts[0]
            s = await b.new_browser_cdp_session()
            await s.send("Browser.grantPermissions", {"origin": rig.ORIGIN, "permissions": ["notifications"]})
            pg = await ctx.new_page()
            await pg.goto(rig.ORIGIN + "/settings")
            await pg.evaluate("navigator.serviceWorker.register('/sw.js',{scope:'/'}).then(()=>navigator.serviceWorker.ready).then(()=>1)")
            await pg.evaluate("""()=>{window.__m=[];navigator.serviceWorker.addEventListener('message',e=>window.__m.push(e.data))}""")
            for name, js in CASES.items():
                if only and name not in only:
                    continue
                if "@" in name:
                    continue
                if os.environ.get("E2E_FOCUS"):
                    rig.log("focus ->", os.environ["E2E_FOCUS"], rig.bridge_scpt(FOCUS[os.environ["E2E_FOCUS"]], 30))
                    await asyncio.sleep(1.5)
                    rig.log("frontmost:", rig.bridge_scpt('tell application "System Events" to return name of first process whose frontmost is true', 30))
                rig.log("ax clear:", rig.ax_clear("E2EX"))
                r = await pg.evaluate(js) if isinstance(js, str) else await pg.evaluate(js[0], js[1])
                await asyncio.sleep(1.5)
                shown = await pg.evaluate("navigator.serviceWorker.ready.then(r=>r.getNotifications()).then(a=>a.map(n=>n.title))")
                res = rig.ax_press("E2EX")
                await asyncio.sleep(4)
                try:
                    clicked = await pg.evaluate("window.__c||null")
                except Exception:  # noqa: BLE001
                    clicked = "page navigated"
                shownmsgs = None
                for w_ in ctx.service_workers:
                    if w_.url.startswith(rig.ORIGIN):
                        shownmsgs = await w_.evaluate("self.__e2e.splice(0)")
                sw = await rig.sw_state(ctx)
                pages = await rig.page_targets(b)
                out[name] = {"created": r, "getNotifications": shown, "ax": res, "page_events": clicked,
                             "sw_events": shownmsgs, "pages": len(pages)}
                rig.log(name, json.dumps(out[name]))
                await asyncio.sleep(1)
    finally:
        if os.environ.get("ASB_E2E_CHROME_FLAGS"):
            lg = rig.ssh(f"grep -a -E 'notif|Notif|persistent|Persistent' {rig.PROFILE}/chrome_debug.log | tail -80 | cut -c1-330").stdout
            open("/tmp/asb-e2e-chrome-log.txt", "w").write(lg)
        tun.down()
        rig.chrome_down()
        broker.down()
    print(json.dumps(out, indent=1))


asyncio.run(main())

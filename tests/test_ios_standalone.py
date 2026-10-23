"""iOS home-screen app: safe-area header, head meta tags, manifest and icon (issue #11), and
signed-out handling, manual reload and automatic recovery in the page scripts (issue #12)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only)

from secret_broker import broker as bmod  # noqa: E402


class Pages(t.Dashboard):
    ttl = 300

    def hdr(self, path, user="alice"):
        r = urllib.request.Request(self.abase + path, headers={"X-authentik-username": user})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def pages(self):
        rid = self.ask()
        nonce = self.broker._by_id[rid].nonce
        return {"/": 200, "/settings": 200, "/policies": 200, f"/a/{nonce}": 200, "/a/bogus": 404}

    def test_head_meta_on_every_page_type(self):
        for path, code in self.pages().items():
            st, hd, body = self.hdr(path)
            self.assertEqual(st, code, path)
            b = body.decode()
            self.assertIn("viewport-fit=cover", b, path)
            self.assertIn("<meta name=theme-color content='#f3f6f1' media='(prefers-color-scheme: light)'>", b)
            self.assertIn("<meta name=theme-color content='#0c140f' media='(prefers-color-scheme: dark)'>", b)
            self.assertIn("<meta name=apple-mobile-web-app-capable content=yes>", b)
            self.assertIn("<meta name=mobile-web-app-capable content=yes>", b)
            self.assertIn("<meta name=apple-mobile-web-app-status-bar-style content=default>", b)
            self.assertIn("<meta name=apple-mobile-web-app-title content='Secret Broker'>", b)
            self.assertRegex(b, r'<link rel=apple-touch-icon sizes=180x180 href="data:image/png;base64,')
            self.assertIn("<link rel=manifest href=/manifest.webmanifest crossorigin=use-credentials>", b)
            self.assertIn("id=asb-reload", b, path)         # header reload control (shown in standalone only)
            self.assertIn("id=signedout", b, path)
            self.assertIn("asbAuth", b, path)

    def test_forbidden_page_has_head_but_no_scripts(self):
        st, hd, body = self.hdr("/", user="mallory")
        self.assertEqual(st, 403)
        b = body.decode()
        self.assertIn("viewport-fit=cover", b)
        self.assertNotIn("<script", b)
        self.assertNotIn("id=asb-reload", b)

    def test_csp_only_gains_manifest_src(self):
        st, hd, body = self.hdr("/")
        csp = re.sub(r"'nonce-[^']+'", "'nonce-X'", hd["Content-Security-Policy"])
        self.assertEqual(csp, "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                              "form-action 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; "
                              "frame-ancestors 'none'; worker-src 'self'; script-src 'nonce-X'")

    def test_safe_area_css(self):
        from secret_broker import ui_theme
        css = ui_theme.TOKENS + bmod._CSS
        top = re.search(r"\.top\{([^}]*)\}", css).group(1)
        self.assertIn("background:var(--card)", top)             # opaque header surface
        self.assertIn("env(safe-area-inset-top", top)
        self.assertIn("env(safe-area-inset-left", top)
        self.assertIn("env(safe-area-inset-right", top)
        self.assertIn("env(safe-area-inset-bottom", re.search(r"\nmain\{([^}]*)\}", css).group(1))
        self.assertIn("env(safe-area-inset-bottom", re.search(r"\.dbody\{([^}]*)\}", css).group(1))
        self.assertIn("safe-area-inset-left", re.search(r"\.tabs\{--edge[^}]*\}", css).group(0))
        # every inset has a 0 fallback, so a normal tab renders as before
        for m in re.finditer(r"env\(([a-z-]+)([^)]*)\)", css):
            self.assertEqual(m.group(2), ",0px", m.group(0))
        # theme-color matches the header surface in both schemes
        light = re.search(r"--bg:(#[0-9a-f]+)", css).group(1)
        dark = re.search(r"prefers-color-scheme:dark\)\{:root:not\(\[data-theme=light\]\)\{[^}]*--bg:(#[0-9a-f]+)",
                         css).group(1)
        self.assertEqual(bmod._THEME_LIGHT, "#f3f6f1")
        self.assertEqual((light, dark), (bmod._THEME_LIGHT, bmod._THEME_DARK))

    def test_manifest(self):
        st, hd, body = self.hdr("/manifest.webmanifest")
        self.assertEqual(st, 200)
        self.assertTrue(hd["Content-Type"].startswith("application/manifest+json"))
        m = json.loads(body)
        self.assertEqual((m["display"], m["start_url"], m["scope"]), ("standalone", "/", "/"))
        self.assertEqual(m["name"], "Agent Secret Broker")
        self.assertIn("theme_color", m)
        self.assertIn("background_color", m)
        self.assertEqual(m["icons"][0]["src"], "/apple-touch-icon.png")
        self.assertEqual(self.hdr("/manifest.webmanifest", user="mallory")[0], 403)   # same gate as pages

    def test_icon_asset(self):
        st, hd, body = self.hdr("/apple-touch-icon.png")
        self.assertEqual(st, 200)
        self.assertEqual(hd["Content-Type"], "image/png")
        self.assertEqual(body[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(int.from_bytes(body[16:20], "big"), 180)
        self.assertEqual(int.from_bytes(body[20:24], "big"), 180)
        self.assertEqual(body, open(os.path.join(os.path.dirname(bmod.__file__), "assets",
                                                 "sb-monogram-180.png"), "rb").read())
        self.assertEqual(self.hdr("/apple-touch-icon.png", user="mallory")[0], 403)
        # the same bytes are inlined, so the home-screen icon needs no extra (SSO-gated) fetch
        import base64
        self.assertIn(base64.b64encode(body).decode(), self.hdr("/")[2].decode())


for _n in dir(t.Dashboard):         # reuse its helpers, not its tests
    if _n.startswith("test"):
        setattr(Pages, _n, None)


HARNESS = r"""
const vm=require('vm'),fs=require('fs');
const dir=process.argv[2];
const src=n=>fs.readFileSync(dir+'/'+n+'.js','utf8');
const clock={t:1700000000000};
const RD=Date;
function FD(...a){return a.length?new RD(...a):new RD(clock.t);}
FD.now=()=>clock.t;
function el(attrs){const e={hidden:true,attrs:attrs||{},ls:{},textContent:'',innerHTML:'',
  getAttribute(k){return this.attrs[k]===undefined?null:this.attrs[k];},setAttribute(k,v){this.attrs[k]=v;},
  addEventListener(t,f){this.ls[t]=f;},focus(){this.focused=true;},
  querySelectorAll(){return [];},querySelector(){return null;}};return e;}
const state={hidden:false,open:false,standalone:false,mm:false,storeThrows:false,get:true,cards:true,
  fetches:[],reloads:0,assigns:[],timers:[],store:{}};
const els={signedout:el(),'so-btn':el(),'asb-reload':el()};
els.offline=el();els.flash=el();
if(true){els.cards=el({'data-version':'v1'});els.cards.hidden=false;}
const L={};
const doc={get hidden(){return state.hidden;},get visibilityState(){return state.hidden?'hidden':'visible';},
  hasFocus(){return true;},title:'',
  getElementById(id){return els[id]||null;},
  querySelector(){return state.open?{}:null;},querySelectorAll(){return [];},
  addEventListener(t,f){L[t]=f;}};
class DOMParserX{parseFromString(h){return {getElementById(id){
  if(id==='cards'&&h.indexOf('id=cards')>=0)return {getAttribute(){return 'v1';},innerHTML:'x'};
  return null;}};}}
function resp(o){o=o||{};const s=o.status===undefined?200:o.status;
  return {type:o.type||'basic',status:s,ok:s>=200&&s<300,redirected:!!o.redirected,
    headers:{get:k=>/content-type/i.test(k)?(o.ct||null):null},text:()=>Promise.resolve(o.body||'')};}
const routes={'/push/event':()=>resp({status:204}),'/presence':()=>resp({status:204}),
  '/?fragment=1':()=>resp({ct:'text/html',body:'<div id=cards></div>'})};
function route(u){const base=u.split('&')[0];return routes[base]||routes[u];}
const sb={document:doc,DOMParser:DOMParserX,Date:FD,URLSearchParams,URL,Uint8Array,
  navigator:{get standalone(){return state.standalone?true:undefined;}},
  history:{replaceState(){}},
  location:{pathname:'/',reload(){state.reloads++;},assign(u){state.assigns.push(u);}},
  sessionStorage:{getItem(k){if(state.storeThrows)throw new Error('x');return k in state.store?state.store[k]:null;},
    setItem(k,v){if(state.storeThrows)throw new Error('x');state.store[k]=v;}},
  localStorage:{getItem(){return null;},setItem(){}},
  fetch(u,o){state.fetches.push(u);const r=route(u);
    if(typeof r==='function'){const v=r(u,o);if(v&&v.__reject)return Promise.reject(new TypeError('net'));return Promise.resolve(v);}
    return Promise.reject(new TypeError('net'));},
  setInterval(f,ms){state.timers.push({f,ms});return state.timers.length;},clearInterval(){},
  setTimeout(f,ms){return 0;},clearTimeout(){}};
sb.window=sb;sb.self=sb;
sb.window.matchMedia=q=>({matches:state.mm&&/standalone/.test(q)});
sb.addEventListener=(t,f)=>{L['w:'+t]=f;};
vm.createContext(sb);
function run(n){vm.runInContext(src(n),sb);}
const tick=()=>new Promise(r=>setImmediate(()=>setImmediate(r)));
const out={};
const hr=()=>({__reject:true});
(async()=>{
%SCENARIO%
console.log(JSON.stringify(out));
})().catch(e=>{console.error(e);process.exit(1);});
"""


class NodeBase(unittest.TestCase):
    def js(self, scenario, scripts=("session",)):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        d = tempfile.mkdtemp()
        srcs = {"session": bmod._SESSION_JS, "dash": bmod._DASH_JS, "presence": bmod._PRESENCE_JS}
        for n, code in srcs.items():
            with open(os.path.join(d, n + ".js"), "w") as f:
                f.write(code)
            chk = subprocess.run([node, "--check", os.path.join(d, n + ".js")], capture_output=True, text=True)
            self.assertEqual(chk.returncode, 0, chk.stderr)
        with open(os.path.join(d, "h.js"), "w") as f:
            f.write(HARNESS.replace("%SCENARIO%", scenario))
        r = subprocess.run([node, os.path.join(d, "h.js"), d], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        shutil.rmtree(d, ignore_errors=True)
        return json.loads(r.stdout.strip().splitlines()[-1])


FULL = """
sb.ASB_PAGE={get:state.get};run('session');run('dash');
sb.ASB_PRESENCE={every:10000,focus:false};run('presence');
await tick();
const poll=()=>state.timers.find(t=>t.ms===3000).f();
const beat=()=>state.timers.find(t=>t.ms===10000).f();
"""


class SignedOut(NodeBase):
    def scenario_signed_out(self, route_js):
        return self.js(FULL + route_js + """
state.fetches.length=0;
poll(); await tick();
out.banner=els.signedout.hidden; out.offline=els.offline.hidden; out.afterPoll=state.fetches.length;
state.fetches.length=0;
poll();poll();beat();beat();
doc_vis=L.visibilitychange; state.hidden=true;doc_vis();state.hidden=false;doc_vis();
sb.dispatch=null;if(L['w:focus'])L['w:focus']();
await tick();
out.more=state.fetches.slice();out.out=sb.asbAuth.out;
""", ("session", "dash", "presence"))

    def check_signed_out(self, route_js):
        o = self.scenario_signed_out(route_js)
        self.assertFalse(o["banner"], o)             # banner shown
        self.assertTrue(o["offline"], o)             # offline note stays hidden
        self.assertEqual(o["afterPoll"], 1)
        self.assertTrue(o["out"])
        self.assertEqual(o["more"], [])              # no more polls, heartbeats or reports

    def test_opaqueredirect(self):
        self.check_signed_out("routes['/?fragment=1']=()=>resp({type:'opaqueredirect',status:0});")

    def test_401(self):
        self.check_signed_out("routes['/?fragment=1']=()=>resp({status:401});")

    def test_403(self):
        self.check_signed_out("routes['/?fragment=1']=()=>resp({status:403});")

    def test_followed_redirect(self):
        self.check_signed_out("routes['/?fragment=1']=()=>resp({redirected:true,ct:'text/html',body:'<html>sign in'});")

    def test_html_login_body_with_200(self):
        self.check_signed_out("routes['/?fragment=1']=()=>resp({ct:'text/html',body:'<html><form>Log in</form>'});")

    def test_heartbeat_sees_redirect(self):
        o = self.js(FULL + """
routes['/presence']=()=>resp({type:'opaqueredirect',status:0});
state.fetches.length=0;
beat(); await tick();
out.banner=els.signedout.hidden;
state.fetches.length=0;beat();beat();poll();await tick();out.more=state.fetches.slice();
""")
        self.assertFalse(o["banner"])
        self.assertEqual(o["more"], [])

    def test_heartbeat_html_body_instead_of_204(self):
        o = self.js(FULL + """
routes['/presence']=()=>resp({status:200,ct:'text/html; charset=utf-8',body:'<html>login'});
beat(); await tick(); out.banner=els.signedout.hidden;
""")
        self.assertFalse(o["banner"])

    def test_normal_poll_is_silent(self):
        o = self.js(FULL + """
poll();await tick();out.banner=els.signedout.hidden;out.offline=els.offline.hidden;out.out=sb.asbAuth.out;
""")
        self.assertEqual((o["banner"], o["offline"], o["out"]), (True, True, False))

    def test_network_error_shows_offline_not_signed_out(self):
        o = self.js(FULL + """
routes['/?fragment=1']=()=>hr();
poll();await tick();
out.banner=els.signedout.hidden;out.offline=els.offline.hidden;out.out=sb.asbAuth.out;
state.fetches.length=0;poll();await tick();out.again=state.fetches.length;
routes['/?fragment=1']=()=>resp({ct:'text/html',body:'<div id=cards></div>'});
poll();await tick();out.recovered=els.offline.hidden;
""")
        self.assertTrue(o["banner"])                 # signed-out banner stays hidden
        self.assertFalse(o["offline"])               # existing offline note shown
        self.assertFalse(o["out"])
        self.assertEqual(o["again"], 1)              # still polling
        self.assertTrue(o["recovered"])

    def test_server_error_is_offline_not_signed_out(self):
        o = self.js(FULL + """
routes['/?fragment=1']=()=>resp({status:502});
poll();await tick();out.banner=els.signedout.hidden;out.offline=els.offline.hidden;
""")
        self.assertTrue(o["banner"])
        self.assertFalse(o["offline"])

    def test_fetches_use_manual_redirect(self):
        o = self.js(FULL.replace("run('session');", "run('session');sb.fetch0=sb.fetch;sb.fetch=function(u,o){"
                                 "(sb.opts=sb.opts||{})[u]=o;return sb.fetch0(u,o);};") + """
poll();beat();await tick();out.opts=sb.opts;
""")
        for u in ("/?fragment=1", "/presence", "/push/event"):
            self.assertEqual(o["opts"][u]["redirect"], "manual", u)

    def test_button_navigates_to_root(self):
        o = self.js(FULL + """
routes['/?fragment=1']=()=>resp({status:401});
poll();await tick();
els['so-btn'].ls.click();
out.assigns=state.assigns;out.reloads=state.reloads;out.focused=!!els['so-btn'].focused;
""")
        self.assertEqual(o["assigns"], ["/"])
        self.assertEqual(o["reloads"], 0)
        self.assertTrue(o["focused"])

    def test_decide_post_redirect_failure_polls_to_tell_why(self):
        # an SSO redirect on the POST is a CORS failure (indistinguishable from offline); the poll sorts it out
        o = self.js("""
els.f={hidden:false};
const form={attrs:{},getAttribute(k){return this.attrs[k]||null;},setAttribute(k,v){this.attrs[k]=v;},
  action:'/decide',ls:{},addEventListener(t,f){this.ls[t]=f;},querySelectorAll(){return [];}};
doc.querySelectorAll=s=>s==='form.decide'?[form]:[];
sb.FormData=class{};
sb.ASB_PAGE={get:true};run('session');run('dash');await tick();
routes['/decide']=()=>hr();
routes['/?fragment=1']=()=>resp({type:'opaqueredirect',status:0});
form.ls.submit({preventDefault(){},submitter:{name:'decision',value:'approve'}});
await tick();await tick();
out.banner=els.signedout.hidden;out.offline=els.offline.hidden;
""")
        self.assertFalse(o["banner"])
        self.assertTrue(o["offline"])


class Recovery(NodeBase):
    LONG = """
sb.ASB_PAGE={get:state.get};run('session');
routes['/?fragment=1']=()=>%s;
const away=async(ms)=>{state.hidden=true;L.visibilitychange();clock.t+=ms;state.hidden=false;
  state.fetches.length=0;L.visibilitychange();await tick();};
"""
    LOGIN = "resp({type:'opaqueredirect',status:0})"
    OK = "resp({ct:'text/html',body:'<div id=cards></div>'})"

    def go(self, body, probe=None):
        return self.js((self.LONG % (probe or self.LOGIN)) + body + """
out.reloads=state.reloads;out.banner=els.signedout.hidden;out.fetches=state.fetches.slice();
out.stamp=state.store.asb_auto_reload||null;
""")

    def test_long_absence_signed_out_reloads_once_and_remembers(self):
        o = self.go("await away(6*60000);")
        self.assertEqual(o["reloads"], 1)
        self.assertTrue(o["banner"])
        self.assertIsNotNone(o["stamp"])

    def test_each_absence_reloads_at_most_once(self):
        o = self.go("await away(6*60000);const first=state.reloads;"
                    "state.hidden=true;L.visibilitychange();clock.t+=5*60000+1000;state.hidden=false;"
                    "sb.asbAuth.out=false;L.visibilitychange();await tick();out.first=first;")
        # a second return 5+ min later is outside the 60 s window, so it may reload again; the point
        # is that the stamp from the first reload is what gates it (see the next tests)
        self.assertEqual(o["reloads"], 2)

    def test_stamp_inside_window_blocks_reload(self):
        o = self.js((self.LONG % self.LOGIN) + """
state.hidden=true;L.visibilitychange();clock.t+=6*60000;
state.store.asb_auto_reload=String(clock.t-30000);       // a reload happened 30 s ago
state.hidden=false;L.visibilitychange();await tick();
out.reloads=state.reloads;out.banner=els.signedout.hidden;
""")
        self.assertEqual(o["reloads"], 0)
        self.assertFalse(o["banner"])                # offered the banner instead

    def test_stamp_older_than_window_allows_reload(self):
        o = self.js((self.LONG % self.LOGIN) + """
state.hidden=true;L.visibilitychange();clock.t+=6*60000;
state.store.asb_auto_reload=String(clock.t-61000);
state.hidden=false;L.visibilitychange();await tick();
out.reloads=state.reloads;
""")
        self.assertEqual(o["reloads"], 1)

    def test_open_menu_or_dialog_is_never_reloaded(self):
        o = self.go("state.open=true;await away(6*60000);")
        self.assertEqual(o["reloads"], 0)
        self.assertFalse(o["banner"])

    def test_unusable_session_storage_means_no_auto_reload(self):
        o = self.go("state.storeThrows=true;await away(6*60000);")
        self.assertEqual(o["reloads"], 0)
        self.assertFalse(o["banner"])

    def test_short_absence_does_not_probe(self):
        o = self.go("await away(60000);")
        self.assertEqual((o["reloads"], o["fetches"]), (0, []))
        self.assertTrue(o["banner"])

    def test_still_signed_in_after_long_absence_does_nothing(self):
        o = self.go("await away(6*60000);", probe=self.OK)
        self.assertEqual(o["reloads"], 0)
        self.assertTrue(o["banner"])
        self.assertEqual(o["fetches"], ["/?fragment=1"])

    def test_network_error_on_probe_does_nothing(self):
        o = self.go("await away(6*60000);", probe="hr()")
        self.assertEqual(o["reloads"], 0)
        self.assertTrue(o["banner"])

    def test_post_result_page_offers_banner_not_reload(self):
        o = self.go("state.get=false;sb.ASB_PAGE={get:false};run('session');await away(6*60000);")
        self.assertEqual(o["reloads"], 0)
        self.assertFalse(o["banner"])


class ReloadButton(NodeBase):
    def btn(self, setup, click=True, get=True):
        return self.js(f"""
{setup}
sb.ASB_PAGE={{get:{'true' if get else 'false'}}};run('session');
out.hidden=els['asb-reload'].hidden;
if({'true' if click else 'false'})els['asb-reload'].ls.click();
out.reloads=state.reloads;out.assigns=state.assigns;
""")

    def test_shown_in_standalone_and_reloads(self):
        o = self.btn("state.standalone=true;")
        self.assertFalse(o["hidden"])
        self.assertEqual(o["reloads"], 1)

    def test_shown_for_display_mode_standalone(self):
        o = self.btn("state.mm=true;", click=False)
        self.assertFalse(o["hidden"])

    def test_hidden_in_a_normal_tab(self):
        o = self.btn("", click=False)
        self.assertTrue(o["hidden"])

    def test_after_post_goes_to_root_instead_of_resubmitting(self):
        o = self.btn("state.standalone=true;", get=False)
        self.assertEqual((o["reloads"], o["assigns"]), (0, ["/"]))


if __name__ == "__main__":
    unittest.main()

"""Look and feel of the approval site: design tokens (light and dark), component CSS, the logo and
icon assets, risk chips, UTC time tags and the two small page scripts (theme, local time).

Nothing here touches broker state. Pure functions and constants, no I/O after import.
The mockup spec is described in docs/proposals/ui-redesign.md.
"""
import base64
import html
import time

from . import icon as icon_mod

# ---------------------------------------------------------------- assets
SIZES = (32, 64, 180, 512)
ICONS = {s: icon_mod.load(s) for s in SIZES}
# path -> (bytes, content type). /apple-touch-icon.png is the 180 px icon under its old name.
ICON_ROUTES = {f"/icon-{s}.png": (ICONS[s], "image/png") for s in SIZES}
ICON_ROUTES["/apple-touch-icon.png"] = (ICONS[180], "image/png")
ICON_CACHE = "private, max-age=31536000"


def _uri(size):
    return "data:image/png;base64," + base64.b64encode(ICONS[size]).decode()


# Inlined so the Content-Security-Policy keeps img-src 'data:' (no same-origin image loads) and the
# icons need no extra fetch through the SSO proxy.
LOGO_URI, FAVICON_URI, TOUCH_URI = _uri(64), _uri(32), _uri(180)

# ---------------------------------------------------------------- tokens
_LIGHT = ("--bg:#f3f6f1;--sf:#ffffff;--tx:#14201a;--mu:#53635a;--ln:#dde6dd;--bt:#8fa396;--ac:#1f6b43;"
          "--ai:#ffffff;--lob:#d3efdc;--lot:#14532d;--mdb:#fdecc8;--mdt:#7a4a00;--hib:#fde1dd;--hit:#a1241a;"
          "--okb:#1f6b43;--okt:#ffffff;--nob:#1d2a22;--not:#ffffff;--exb:#e4ebe4;--ext:#47574e;--tb:#e8efe8;"
          "--dnb:#fdecea;--dnl:#d9534a;--dnt:#a1241a;--shade:#0003")
_DARK = ("--bg:#0c140f;--sf:#141e17;--tx:#e5efe8;--mu:#9db0a4;--ln:#26342b;--bt:#4d6455;--ac:#5fd08a;"
         "--ai:#06180e;--lob:#173826;--lot:#8fe6b0;--mdb:#3a2f12;--mdt:#ffcf6d;--hib:#4a1d1a;--hit:#ffa79b;"
         "--okb:#5fd08a;--okt:#06180e;--nob:#e5efe8;--not:#0c140f;--exb:#202b24;--ext:#9db0a4;--tb:#1a2620;"
         "--dnb:#2c1614;--dnl:#c0504a;--dnt:#ffa79b;--shade:#0008")
# The names the other modules were written with, kept as aliases of the new tokens.
_ALIASES = ("--card:var(--sf);--fg:var(--tx);--muted:var(--mu);--line:var(--ln);--accent:var(--ac);"
            "--ok:var(--ac);--warn:var(--mdt);--bad:var(--hit);--danger:var(--dnl);--dangerh:var(--dnt);"
            "--okbg:var(--lob);--okfg:var(--lot);--wbg:var(--mdb);--wfg:var(--mdt);--badbg:var(--hib);"
            "--hov:var(--tb)")

TOKENS = (
    f":root{{color-scheme:light dark;{_LIGHT};{_ALIASES}}}\n"
    f"@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{{_DARK}}}}}\n"
    f":root[data-theme=light]{{color-scheme:light;{_LIGHT}}}\n"
    f":root[data-theme=dark]{{color-scheme:dark;{_DARK}}}\n")

# ---------------------------------------------------------------- components
CSS = """
body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:42.5rem;padding-top:.9rem}
.bar{max-width:42.5rem}
.top{background:var(--bg);border-bottom:0}
.logo{width:30px;height:30px;border-radius:8px;display:block;background:none}
.brand{font-size:1rem}
.online{margin-left:auto;font-size:.78rem;color:var(--mu);display:inline-flex;gap:6px;align-items:center;white-space:nowrap}
.online i{width:8px;height:8px;border-radius:50%;background:var(--ac);display:inline-block}
.rl{margin-left:.6rem}
.tabs{--edge:max(1rem,calc((100% - 42.5rem)/2 + .6rem));background:transparent;gap:.1rem;border-bottom:1px solid var(--ln)}
.tabs a{min-height:2.75rem;padding:.55rem .65rem .5rem;font-weight:500;font-size:.92rem}
.tabs a.on{color:var(--tx);font-weight:700;border-bottom-color:var(--ac)}
.count{background:var(--ac);color:var(--ai);font-weight:700}
h1{font-size:1.2rem;margin:.1rem 0 .8rem}
h3{font-size:.75rem;letter-spacing:.08em;font-weight:700;margin:1.2rem 0 .5rem}
.card,.req{border-radius:16px;padding:14px}
.card.flush{padding:0}
/* buttons */
.btn,button{border-radius:10px;border:1.5px solid var(--bt);background:transparent;color:var(--tx);min-height:2.75rem;
padding:.3rem 1rem;font-weight:700;transition:background-color .12s,border-color .12s}
.btn:hover,button:hover{background:var(--tb)}
.btn.approve{background:var(--ac);border-color:var(--ac);color:var(--ai)}
.btn.approve:hover{background:var(--ac);filter:brightness(1.08)}
.btn.deny{background:var(--dnb);border-color:var(--dnl);color:var(--dnt)}
.btn.deny:hover{background:var(--dnb);filter:brightness(.97)}
.btn.sm,td button{min-height:2.75rem;padding:.2rem .8rem;font-size:.85rem;border-radius:10px}
.btn.t{background:var(--tb);border-color:transparent;font-size:.9rem}
.btn.t:hover{background:var(--tb);filter:brightness(.96)}
:is(a,.btn,.chip,button,summary,input,select,.sw):focus-visible{outline:2px solid var(--ac);outline-offset:2px}
/* the card */
.glance{display:flex;align-items:center;gap:8px;min-width:0}
.rbadge{font-size:.69rem;font-weight:800;letter-spacing:.06em;border-radius:7px;padding:3px 8px;display:inline-flex;gap:5px;
align-items:center;white-space:nowrap;flex:none;line-height:1.3}
.rbadge.lo{background:var(--lob);color:var(--lot)}.rbadge.md{background:var(--mdb);color:var(--mdt)}
.rbadge.hi{background:var(--hib);color:var(--hit)}.rbadge.na{background:var(--tb);color:var(--mu)}
.gwho{color:var(--mu);font-size:.82rem;min-width:0;flex:1 1 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.left{margin-left:auto;color:var(--mu);font-size:.82rem;white-space:nowrap;flex:none}
.sent{font-size:1.08rem;font-weight:650;line-height:1.3;margin:10px 0 4px;letter-spacing:-.005em;overflow-wrap:anywhere}
.rqmeta{color:var(--mu);font-size:.82rem;overflow-wrap:anywhere}
.callline{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;color:var(--mu);margin-top:4px}
.trunc{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;max-width:100%;display:block}
.decide-row{display:flex;gap:8px;margin:12px 0 0}
.decide-row .btn,.decide-row>details>summary{min-height:2.9rem;border-radius:12px;font-size:.95rem}
.decide-row .btn.deny{flex:1 1 0;order:-1}
.decide-row>.btn.approve,.decide-row>details{flex:2 1 0}
.decide-row>details>summary{display:flex;align-items:center;justify-content:center}
.timed{display:flex;gap:8px;margin-top:8px}
.timed .btn{flex:1 1 0;min-width:0}
.alwrow{display:flex;flex-wrap:wrap;gap:0 14px;align-items:center;margin-top:2px}
.linkish{color:var(--mu);font-size:.82rem;text-decoration:underline;cursor:pointer;display:inline-flex;align-items:center;
min-height:2.75rem;padding:0 2px;list-style:none;background:none;border:0;font-weight:500}
.linkish::-webkit-details-marker{display:none}
.linkish:hover{color:var(--tx);background:none}
.chip.off.linkish{text-decoration:none;opacity:.7;border:0}
details.alw .confirm{border-color:var(--bt);border-radius:12px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.alwrow .chip,.alwrow .chip.always{border:0;background:none;color:var(--mu);text-decoration:underline;font-size:.82rem;
min-height:2.75rem;padding:0 2px;display:inline-flex;align-items:center;font-weight:500}
.alwrow .chip::after{inset:0}
.alwrow .chip:hover{background:none;color:var(--tx)}
.retry{flex:1 0 100%}
.reqdetails{margin-top:0;flex:none}
.reqdetails[open]{flex:1 0 100%}
.reqdetails>summary{position:relative;list-style:none;cursor:pointer;display:inline-flex;align-items:center;font-size:.78rem;
min-height:2rem;padding:.15rem .75rem;border:1px solid var(--ln);border-radius:99px;color:var(--mu);white-space:nowrap}
.reqdetails>summary::-webkit-details-marker{display:none}
.reqdetails>summary::after{content:"";position:absolute;inset:-6px -2px}
.reqdetails[open]>summary{background:var(--tb);color:var(--tx)}
/* chips and disclosures */
.chip{position:relative;font-size:.78rem;font-weight:500;min-height:2rem;padding:.15rem .75rem;border:1px solid var(--ln);
border-radius:99px;color:var(--mu);background:transparent;white-space:nowrap;flex:none;text-decoration:none}
.chip::after{content:"";position:absolute;inset:-6px -2px}
.chip:hover{background:var(--tb)}
.chip.on,.chip[aria-current=true]{background:var(--tx);color:var(--bg);border-color:var(--tx)}
.chips,.dxrow{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center}
.dxrow{margin-top:8px}
details.dx{flex:none;max-width:100%}
details.dx[open]{flex:1 0 100%}
details.dx>summary{position:relative;list-style:none;cursor:pointer;display:inline-flex;align-items:center;font-size:.78rem;
min-height:2rem;padding:.15rem .75rem;border:1px solid var(--ln);border-radius:99px;color:var(--mu);white-space:nowrap}
details.dx>summary::-webkit-details-marker{display:none}
details.dx>summary::after{content:"";position:absolute;inset:-6px -2px}
details.dx[open]>summary{background:var(--tb);color:var(--tx)}
details.dx>.dxbody{min-width:0;padding-top:.4rem}
.facts{display:grid;grid-template-columns:6.2rem minmax(0,1fr);gap:7px 10px;font-size:.88rem;margin:12px 0 4px}
.facts dt{color:var(--mu);margin:0}.facts dd{margin:0;overflow-wrap:anywhere;min-width:0}
.facts .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem}
.line{height:1px;background:var(--ln);margin:12px 0}
.pend{display:flex;gap:6px;align-items:center;font-size:.8rem;color:var(--mu);margin-top:6px}
.sec{font-size:.75rem;letter-spacing:.08em;text-transform:uppercase;color:var(--mu);margin:1.2rem 0 .5rem;font-weight:700}
.sec:first-child{margin-top:.1rem}
/* pills never wrap or shrink */
.pill{white-space:nowrap;flex:none}
.pill.ok{background:var(--lob);color:var(--lot)}.pill.warn{background:var(--mdb);color:var(--mdt)}
.pill.bad{background:var(--hib);color:var(--hit)}.pill.plain{background:var(--tb);color:var(--mu)}
.risk b{white-space:nowrap}
/* running now */
.runrow{display:flex;align-items:center;gap:10px;padding:10px 0;border-top:1px solid var(--ln)}
.runrow:first-of-type{border-top:0}
.runrow .t{min-width:0}.runrow .t b{overflow-wrap:anywhere}
.runrow form{margin:0}
.runrow .btn{min-width:5rem}
/* history */
.hfilters{padding:0 0 .6rem;border:0;display:flex;flex-wrap:wrap;gap:6px 8px}
.hfilters input[type=search]{flex:1 0 100%;font:inherit;min-height:2.75rem;border-radius:12px;border:1.5px solid var(--bt);
padding:.2rem .8rem;background:var(--sf);color:var(--tx)}
.hist{list-style:none;margin:0;padding:0}
.hist li{border-bottom:1px solid var(--ln)}
.hist li.dayh{border:0;padding:0;font-size:.75rem;letter-spacing:.08em;text-transform:uppercase;color:var(--mu);font-weight:700;margin:1rem 0 .1rem}
.hist .hrow{display:flex;align-items:center;gap:12px;width:100%;min-height:3.5rem;padding:10px 2px;border:0;border-radius:0;
background:none;text-align:left;font-weight:400;font-size:inherit;color:var(--tx)}
.hist .hrow:hover{background:var(--tb)}
.hist .what{min-width:0;flex:1}
.hist .what b{display:block;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hist .what small{display:block;color:var(--mu);font-family:inherit;font-size:.82rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hic{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;flex:none;font-size:.88rem}
.hic.ok{background:var(--okb);color:var(--okt)}.hic.no{background:var(--nob);color:var(--not)}.hic.ex{background:var(--exb);color:var(--ext)}
.hfoot{border-top:0;padding-top:.4rem}
.band{display:flex;align-items:center;gap:12px;margin-top:16px;padding:10px 12px;border-radius:12px;background:var(--tb)}
.band .t{min-width:0}
.dcard .sent{font-size:1.18rem;margin-top:14px}
/* settings */
.srow{padding:10px 0}
.srow .btn,.srow button{flex:none}
.seg{display:flex;background:var(--tb);border-radius:12px;padding:3px;gap:2px}
.seg button,.seg span{flex:1;text-align:center;padding:.5rem .2rem;min-height:2.75rem;font-size:.86rem;font-weight:600;
border-radius:9px;color:var(--mu);border:0;background:transparent;display:flex;align-items:center;justify-content:center}
.seg .on{background:var(--ac);color:var(--ai)}
.seg button:hover{background:transparent}
.seg button.on:hover{background:var(--ac)}
.tagchip{font-size:.72rem;border:1px solid var(--ln);border-radius:99px;padding:1px 8px;color:var(--mu);white-space:nowrap}
.devices li{border-top:1px solid var(--ln);padding:.7rem 0}
.devices li:first-child{border-top:0}
/* tables become stacked rows at every width: the column is narrow everywhere */
.tbl{background:transparent;border:0;border-radius:0}
.tbl thead{display:none}
.tbl,.tbl tbody,.tbl tr,.tbl td{display:block;width:100%}
.tbl tr{border:1px solid var(--ln);border-radius:14px;background:var(--sf);padding:.5rem .8rem;margin:0 0 .6rem}
.tbl td{border:0;padding:.2rem 0;display:flex;gap:.75rem}
.tbl td::before{content:attr(data-label);flex:0 0 5.5rem;color:var(--mu);font-size:.8rem;padding-top:.1rem}
.tbl td>*{min-width:0}
.tbl td:last-child:not([data-label])::before{content:none}
dl.kv.facts{grid-template-columns:6.2rem minmax(0,1fr);gap:7px 10px}
.card>.srow:first-child,.line+.srow,.sec+.card>.srow:first-child{border-top:0}
@media (max-width:21rem){.timed{flex-wrap:wrap}.timed .btn{flex:1 1 30%}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important;scroll-behavior:auto!important}}
"""

FULL_CSS = TOKENS + CSS

# ---------------------------------------------------------------- scripts
# Runs in <head>, before first paint: the Appearance choice (light/dark) lives only in this browser.
# No stored value, or storage blocked: the page follows the system setting.
THEME_JS = (
    "try{var t=localStorage.getItem('asb_theme');"
    "if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);}catch(e){}")

# Settings > Appearance: Light / Dark / Match phone. The choice is kept in this browser only
# (localStorage, every access in try/catch); it never reaches the server.
APPEARANCE_JS = r"""
(function(){
  var box=document.getElementById('appearance');if(!box)return;
  function get(){try{var t=localStorage.getItem('asb_theme');return t==='light'||t==='dark'?t:'auto';}catch(e){return 'auto';}}
  function mark(){var cur=get();box.querySelectorAll('button[data-theme-set]').forEach(function(b){
    var on=b.getAttribute('data-theme-set')===cur;b.classList.toggle('on',on);b.setAttribute('aria-pressed',on?'true':'false');});}
  box.addEventListener('click',function(e){var b=e.target.closest('button[data-theme-set]');if(!b)return;
    var v=b.getAttribute('data-theme-set');
    try{if(v==='auto')localStorage.removeItem('asb_theme');else localStorage.setItem('asb_theme',v);}catch(x){}
    if(v==='auto')document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme',v);
    mark();});
  mark();
})();
"""

# Every <time datetime="...Z"> is rewritten in the viewer's own timezone. The element's text is a UTC
# fallback for browsers without scripts; the exact local date and time go in its title. data-fmt:
# clock (time of day), when (time today, date and time otherwise), ago (N min ago), full, day.
# Lists with li[data-ts] under ul.hist get day headings (Today, Yesterday, a date) in local time.
TIME_JS = r"""
(function(){
  var F={};
  try{
    F.clock=new Intl.DateTimeFormat(undefined,{hour:'numeric',minute:'2-digit'});
    F.secs=new Intl.DateTimeFormat(undefined,{hour:'numeric',minute:'2-digit',second:'2-digit'});
    F.full=new Intl.DateTimeFormat(undefined,{year:'numeric',month:'short',day:'numeric',hour:'numeric',
      minute:'2-digit',second:'2-digit',timeZoneName:'short'});
    F.date=new Intl.DateTimeFormat(undefined,{month:'short',day:'numeric'});
    F.day=new Intl.DateTimeFormat(undefined,{weekday:'long',month:'short',day:'numeric'});
  }catch(e){return;}
  function ymd(d){return d.getFullYear()*10000+(d.getMonth()+1)*100+d.getDate();}
  function ago(ms){var s=Math.round(ms/1000);if(s<45)return 'just now';var m=Math.round(s/60);
    if(m<60)return m+' min ago';var h=Math.round(m/60);if(h<24)return h+' h ago';return Math.round(h/24)+' d ago';}
  function one(t){
    var d=new Date(t.getAttribute('datetime'));if(isNaN(d.getTime()))return;
    var f=t.getAttribute('data-fmt')||'clock',txt;
    if(f==='ago')txt=ago(Date.now()-d.getTime());
    else if(f==='full')txt=F.full.format(d);
    else if(f==='secs')txt=F.secs.format(d);
    else if(f==='when')txt=ymd(d)===ymd(new Date())?F.clock.format(d):F.date.format(d)+', '+F.clock.format(d);
    else txt=F.clock.format(d);
    if(t.textContent!==txt)t.textContent=txt;
    t.title=F.full.format(d);}
  function label(d){var n=new Date(),y=new Date(n.getFullYear(),n.getMonth(),n.getDate()-1);
    return ymd(d)===ymd(n)?'Today':ymd(d)===ymd(y)?'Yesterday':F.day.format(d);}
  function days(root){(root||document).querySelectorAll('ul.hist').forEach(function(ul){
    ul.querySelectorAll('li.dayh').forEach(function(h){h.remove();});
    var prev=null;ul.querySelectorAll('li[data-ts]').forEach(function(li){
      var d=new Date(+li.getAttribute('data-ts')*1000);if(isNaN(d.getTime()))return;
      var k=ymd(d);if(k===prev)return;prev=k;
      var h=document.createElement('li');h.className='dayh';h.setAttribute('role','presentation');
      h.textContent=label(d);ul.insertBefore(h,li);});});}
  var obs=null;
  function run(root){
    (root||document).querySelectorAll('time[datetime]').forEach(one);days(root);
    if(obs)obs.takeRecords();}
  window.asbTime={run:run,ago:ago};
  run(document);
  if(window.MutationObserver){
    var q=0;
    obs=new MutationObserver(function(ms){
      var add=false;
      ms.forEach(function(m){m.addedNodes.forEach(function(n){if(n.nodeType===1)add=true;});});
      if(add&&!q)q=setTimeout(function(){q=0;run(document);},0);});
    obs.observe(document.body,{childList:true,subtree:true});}
  setInterval(function(){run(document);},30000);
})();
"""


# ---------------------------------------------------------------- helpers
RISK_CHIPS = {"low": ("lo", "&#9679;", "LOW"), "medium": ("md", "&#9670;", "MEDIUM"),
              "high": ("hi", "&#9650;", "HIGH")}


def risk_chip(level):
    """Icon, word and colour for a risk level; an unrated request gets a neutral 'ASSESSING' chip."""
    cls, icon, word = RISK_CHIPS.get(level, ("na", "&#9675;", "ASSESSING"))
    return f"<span class='rbadge {cls}'><i aria-hidden=true>{icon}</i>{word}</span>"


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def time_tag(ts, fmt="clock", cls="", fallback=None):
    """<time datetime="...Z"> for the page script to format in the viewer's timezone. The text is a UTC
    fallback ("09:41 UTC"), shown only when the script does not run."""
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return ""
    when = time.gmtime(ts)
    text = (time.strftime("%H:%M UTC", when) if fmt in ("clock", "when", "ago")
            else time.strftime("%H:%M:%S UTC", when) if fmt == "secs"
            else time.strftime("%Y-%m-%d %H:%M:%S UTC", when))
    if fallback is not None:
        text = html.escape(str(fallback))
    c = f" class={html.escape(cls)}" if cls else ""
    return f"<time{c} datetime='{iso(ts)}' data-fmt={fmt}>{text}</time>"


def stamp_tag(text, fmt="when"):
    """A stored UTC stamp ("2026-10-22T16:41:03Z" or "2026-10-22 16:41:03 UTC") as a <time> tag that keeps the
    original text as its fallback; text that is not such a stamp comes back escaped and unchanged."""
    import calendar
    s = str(text or "")
    for pat in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S UTC"):
        try:
            return time_tag(calendar.timegm(time.strptime(s, pat)), fmt, fallback=s)
        except ValueError:
            continue
    return html.escape(s)


def left_text(seconds):
    """Countdown text, m:ss, for the time left on a card."""
    s = max(0, int(seconds))
    return f"{s // 60}:{s % 60:02d} left"

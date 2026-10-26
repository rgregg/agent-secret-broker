#!/usr/bin/env python3
"""One-shot VNC session daemon for the one-time macOS privacy grants (not part of the normal rig run).

Run it ONLY through the secret broker so the Mac login arrives as env vars and never touches disk:
    asb NAME -- python tools/e2e_push/vncd.py --user-env VAR_FOR_USER --pass-env VAR_FOR_PASSWORD
It authenticates to localhost:15900 (ssh -L to the Mac's Screen Sharing, Apple Remote Desktop auth), then
serves JSON lines on a 0600 unix socket so an operator can screenshot / click / type without
re-authenticating. `typesecret` types the password into the focused field and never returns it; the login
is never printed, logged or written anywhere. Exits on `quit` or after --ttl seconds.
Ops: shot{path,x,y,w,h} click dblclick move scroll{n,dir} type typesecret typeuser key reconnect quit
"""
import argparse
import asyncio
import json
import os
import struct
import sys
import time

import asyncvnc

SOCK = os.environ.get("VNCD_SOCK", "/tmp/asb-e2e-vnc.sock")
DBG = os.environ.get("VNCD_DBG", "/tmp/asb-e2e-vncd.dbg")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=15900)
    ap.add_argument("--ttl", type=int, default=1200)
    ap.add_argument("--user-env", default="ASB_E2E_VNC_USERNAME", help="env var holding the Mac login name")
    ap.add_argument("--pass-env", default="ASB_E2E_VNC_PASSWORD", help="env var holding the Mac login password")
    a = ap.parse_args()
    user, pw = os.environ.get(a.user_env), os.environ.get(a.pass_env)
    if not user or not pw:
        sys.exit("login env vars missing")
    for k in (a.user_env, a.pass_env):
        os.environ.pop(k, None)
    dbg = open(DBG, "a")

    def d(*x):
        dbg.write(time.strftime("%H:%M:%S ") + " ".join(map(str, x)) + "\n")
        dbg.flush()
    end = time.time() + a.ttl
    done = asyncio.Event()
    st = {"c": None, "frame": asyncio.Event(), "task": None, "enc": [0], "region": None}

    # asyncvnc asks for ZLib only; make the encodings list configurable (st["enc"])
    orig_create = asyncvnc.Video.create.__func__

    async def video_create(cls, reader, writer):
        v = await orig_create(cls, reader, writer)
        enc = st["enc"]
        writer.write(struct.pack(">BxH", 2, len(enc)) + b"".join(struct.pack(">i", e) for e in enc))
        return v
    asyncvnc.Video.create = classmethod(video_create)

    async def pump(c):
        try:
            while True:
                t = await c.read()
                rg = st["region"]
                ok = False
                if rg and c.video.data is not None:
                    x, y, w_, h_ = rg
                    ok = bool(c.video.data[y:y + h_, x:x + w_, 3].all())
                d("update", t, "region_complete=" + str(ok))
                if ok:
                    st["frame"].set()
        except Exception as e:  # noqa: BLE001
            d("pump ended", type(e).__name__, str(e)[:80])

    async def connect():
        if st["task"]:
            st["task"].cancel()
        try:
            if st["c"]:
                st["c"].writer.close()
        except Exception:  # noqa: BLE001
            pass
        r, w = await asyncio.open_connection("localhost", a.port)
        c = await asyncvnc.Client.create(r, w, username=user, password=pw)
        d("connected", c.video.width, c.video.height, c.video.mode, "enc", st["enc"])
        st["c"] = c
        st["frame"].clear()
        st["task"] = asyncio.create_task(pump(c))
        return c

    await connect()
    print("connected", flush=True)

    async def handle(r, w):
        try:
            m = json.loads(await r.readline())
            op = m["op"]
            out = {"ok": True}
            if op != "reconnect" and st["task"] is not None and st["task"].done():
                d("connection lost; reconnecting")
                await connect()
            c = st["c"]
            if op == "shot":
                from PIL import Image
                W, H = c.video.width, c.video.height
                x, y = max(0, min(m.get("x", 0), W - 1)), max(0, min(m.get("y", 0), H - 1))
                w_, h_ = min(m.get("w", 1600), W - x), min(m.get("h", 900), H - y)
                for attempt in (1, 2):
                    st["frame"].clear()
                    st["region"] = (x, y, w_, h_)
                    c.video.data = None
                    c.video.refresh(x, y, w_, h_)
                    await c.drain()
                    fw = asyncio.ensure_future(st["frame"].wait())
                    await asyncio.wait([fw, st["task"]], timeout=m.get("timeout", 30),
                                       return_when=asyncio.FIRST_COMPLETED)
                    fw.cancel()
                    if st["frame"].is_set():
                        break
                    if attempt == 1 and st["task"].done():
                        d("connection lost during shot; reconnecting")
                        c = await connect()
                        continue
                    raise TimeoutError("no frame")
                Image.fromarray(c.video.as_rgba()[y:y + h_, x:x + w_]).convert("RGB").save(m["path"])
                out["size"] = [W, H]
            elif op == "reconnect":
                if "enc" in m:
                    st["enc"] = m["enc"]
                await connect()
            elif op == "move":
                c.mouse.move(m["x"], m["y"])
            elif op == "click":
                c.mouse.move(m["x"], m["y"])
                c.mouse.click()
            elif op == "dblclick":
                c.mouse.move(m["x"], m["y"])
                c.mouse.click()
                c.mouse.click()
            elif op == "scroll":
                for _ in range(m.get("n", 5)):
                    (c.mouse.scroll_down if m.get("dir", "down") == "down" else c.mouse.scroll_up)()
            elif op == "type":
                c.keyboard.write(m["text"])
            elif op == "typesecret":
                c.keyboard.write(pw)
            elif op == "typeuser":
                c.keyboard.write(user)
            elif op == "key":
                c.keyboard.press(*m["keys"])
            elif op == "quit":
                done.set()
            else:
                out = {"ok": False, "err": "unknown op"}
            try:
                await st["c"].drain()
            except Exception:  # noqa: BLE001
                pass
            w.write((json.dumps(out) + "\n").encode())
            await w.drain()
        except Exception as e:  # noqa: BLE001
            d("op failed", type(e).__name__, str(e)[:80])
            w.write((json.dumps({"ok": False, "err": type(e).__name__ + ": " + str(e)[:200]}) + "\n").encode())
        finally:
            w.close()
    try:
        os.unlink(SOCK)
    except OSError:
        pass
    old = os.umask(0o177)
    srv = await asyncio.start_unix_server(handle, SOCK)
    os.umask(old)
    while not done.is_set() and time.time() < end:
        try:
            await asyncio.wait_for(done.wait(), 1)
        except asyncio.TimeoutError:
            pass
    srv.close()
    os.unlink(SOCK)
    print("bye", flush=True)

asyncio.run(main())

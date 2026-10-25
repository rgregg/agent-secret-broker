#!/usr/bin/env python3
"""Client for vncd.py: vnc.py shot PATH [X Y W H] | click X Y | dblclick X Y | move X Y | type TEXT | secret | user | key K [K..] | reconnect [ENC..] | quit"""
import json
import os
import socket
import sys

SOCK = os.environ.get("VNCD_SOCK", "/tmp/asb-e2e-vnc.sock")
a = sys.argv[1:]
op = a[0]
if op == "reconnect":
    pass
m = {"op": {"secret": "typesecret", "user": "typeuser"}.get(op, op)}
if op == "shot":
    m["path"] = a[1]
    if len(a) > 5:
        m["x"], m["y"], m["w"], m["h"] = map(int, a[2:6])
elif op in ("click", "dblclick", "move"):
    m["x"], m["y"] = int(a[1]), int(a[2])
elif op == "type":
    m["text"] = a[1]
elif op == "reconnect" and len(a) > 1:
    m["enc"] = [int(x) for x in a[1:]]
elif op == "scroll":
    m["n"] = int(a[1]); m["dir"] = a[2] if len(a) > 2 else "down"
elif op == "key":
    m["keys"] = a[1:]
s = socket.socket(socket.AF_UNIX)
s.connect(SOCK)
s.sendall((json.dumps(m) + "\n").encode())
print(s.makefile().readline().strip())

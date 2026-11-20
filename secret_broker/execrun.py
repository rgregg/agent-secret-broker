"""Run one approved remote command over SSH (request mode `exec`; see execmode.py and the design in
docs/superpowers/specs/2026-11-19-remote-exec-design.md).

The broker has no SSH client of its own, so this drives the OpenSSH binaries, with the key held only in
memory and in a private ssh-agent for the length of the call:

  1. a private directory (0700) holds a known_hosts file generated from the key's pinned lines for this host
     only, and the agent's socket;
  2. `ssh-agent -D -a SOCK` starts an agent, as our own child, that exists for this call alone; the key goes in with `ssh-add -`
     on a PIPE (never argv, an environment variable or a file);
  3. `ssh` runs with a FIXED option list. The request supplies exactly three values, each in a slot that can
     only be a value: the login name after `-l`, the port after `-p`, and, after `--`, the host and the
     command (so none of them can be read as an option);
  4. output is read with a byte cap per stream, decoded, masked, returned. The process is killed at the timeout
     or when a stream passes the cap;
  5. the agent is killed and the directory removed in a `finally`, whatever happened.

Failures are a fixed label from execmode.LABELS, never the text of an exception or of ssh's own output. ssh's
stderr is read only to choose a label when ssh itself failed (exit 255), and is then dropped.

Everything that touches the system is injectable (`popen`, `timer_cls`, the binary directory) so tests drive
it with stub binaries and a clock that fires at once.
"""
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

from . import execmode

# Fixed, in this order. Nothing here is derived from a request. (`-o` values: first one wins in ssh, so the
# request cannot override any of them even if it could name an option, which it cannot.)
FIXED_OPTIONS = (
    "-F", "/dev/null",                          # no user or system configuration
    "-o", "BatchMode=yes",                      # never ask for anything
    "-o", "StrictHostKeyChecking=yes",          # the pinned key or nothing: no trust on first use
    "-o", "UserKnownHostsFile={known_hosts}",   # generated for this call from the key's pinned lines
    "-o", "GlobalKnownHostsFile=/dev/null",
    "-o", "VerifyHostKeyDNS=no",
    "-o", "CheckHostIP=no",
    "-o", "UpdateHostKeys=no",
    "-o", "PreferredAuthentications=publickey",
    "-o", "PubkeyAuthentication=yes",
    "-o", "NumberOfPasswordPrompts=0",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "ClearAllForwardings=yes",
    "-o", "RequestTTY=no",
    "-o", "ControlMaster=no",
    "-o", "ControlPath=none",
    "-o", "ProxyCommand=none",
    "-o", "ProxyJump=none",
    "-o", "PermitLocalCommand=no",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=15",
    # OpenSSH takes `~` from the passwd entry, not $HOME: without this it would also offer the broker user's own
    # ~/.ssh keys. (Not IdentitiesOnly: that would stop it offering the private agent's key too.)
    "-o", "IdentityFile=/dev/null",
)
READ_CHUNK = 65536
_SOCK_MAX = 100                                 # sun_path is 108 bytes

_MISMATCH = re.compile(r"REMOTE HOST IDENTIFICATION HAS CHANGED|Host key for .* has changed|"
                       r"Offending .* key in", re.I)
_NOT_PINNED = re.compile(r"No .* host key is known for|Host key verification failed", re.I)
_AUTH = re.compile(r"Permission denied|Too many authentication failures|no mutual signature", re.I)
_CONNECT = re.compile(r"Connection refused|Connection timed out|Operation timed out|No route to host|"
                      r"Network is unreachable|Could not resolve|Connection closed|Connection reset|"
                      r"kex_exchange_identification|Name or service not known|banner exchange|"
                      r"Host is down|Temporary failure in name resolution", re.I)


def classify_ssh_failure(stderr):
    """The fixed label for an exit-255 run, from ssh's own stderr, or None when it does not look like ssh
    failing (a remote command can exit 255 too). A changed key is checked before 'not pinned' because ssh
    ends both with the same last line."""
    if _MISMATCH.search(stderr):
        return "host_key_mismatch"
    if _NOT_PINNED.search(stderr):
        return "host_not_pinned"
    if _AUTH.search(stderr):
        return "auth_failed"
    if _CONNECT.search(stderr):
        return "connect_failed"
    return None


def _binary(cfg, name):
    d = cfg.get("ssh_path")
    path = os.path.join(d, name) if d else shutil.which(name)
    return path if path and os.access(path, os.X_OK) else None


def _minimal_env(home):
    """What the OpenSSH programs run with: a PATH and a HOME that holds nothing. No broker environment
    (a token, a proxy variable, the SSH_* variables of the broker's own session) reaches them."""
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home, "LANG": "C", "LC_ALL": "C"}


class _Capped:
    """Read one pipe in a thread into a bounded buffer. `over` is set when more than `cap` bytes arrived
    (the excess is discarded); `on_over` is called once so the caller can stop the process."""

    def __init__(self, pipe, cap, on_over):
        self.buf, self.n, self.over, self._cap, self._on_over = bytearray(), 0, False, cap, on_over
        self.thread = threading.Thread(target=self._run, args=(pipe,), daemon=True)
        self.thread.start()

    def _run(self, pipe):
        try:
            while True:
                chunk = pipe.read1(READ_CHUNK)
                if not chunk:
                    return
                room = self._cap - len(self.buf)
                if room > 0:
                    self.buf += chunk[:room]
                if len(chunk) > max(room, 0) and not self.over:
                    self.over = True
                    self._on_over()
                self.n += len(chunk)
        except (OSError, ValueError):
            return


def _start_agent(agent_bin, sock, env):
    """Start a private agent that serves only `sock` and return its Popen. It runs in the foreground (`-D`) as OUR
    child, so it can be waited for: a daemonized agent would be re-parented to the broker's process (PID 1 in a
    container) and linger as a zombie after every call. With -D it prints its first line only once the socket
    is listening, so reading that line is the readiness signal and there is nothing to poll."""
    proc = subprocess.Popen([agent_bin, "-D", "-a", sock], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    watchdog = threading.Timer(10, proc.kill)
    watchdog.daemon = True
    watchdog.start()
    try:
        line = proc.stdout.readline()
    finally:
        watchdog.cancel()
    if not line.startswith(b"SSH_AUTH_SOCK="):
        _stop(proc)
        raise RuntimeError("the agent did not start")
    return proc


def _stop(proc):
    """End and reap a child; SIGTERM first, SIGKILL if it does not go."""
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
        if proc.stdout is not None:
            proc.stdout.close()
    except (OSError, subprocess.SubprocessError):
        pass


def sweep(base):
    """At broker start-up: end any ssh-agent a crashed run left behind and remove its private directory.
    Nothing is in flight at start-up, so every `x-*` directory under `base` is a leftover. A pid in a pid file is
    signalled only when that process really is an ssh-agent."""
    try:
        entries = [e for e in os.listdir(base) if e.startswith(("x-", "asbx-"))]
    except OSError:
        return
    for e in entries:
        d = os.path.join(base, e)
        try:
            with open(os.path.join(d, "agent.pid")) as f:
                pid = int(f.read().strip())
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                words = f.read().split(b"\0")[:2]       # (a script run through an interpreter has it second)
                if any(os.path.basename(w.decode("utf-8", "replace")) == "ssh-agent" for w in words):
                    os.kill(pid, 15)
        except (OSError, ValueError):
            pass
        shutil.rmtree(d, ignore_errors=True)


def run(spec, key_pem, known_hosts_lines, cfg, mask, *, workdir_base=None, popen=subprocess.Popen,
        timer_cls=threading.Timer, clock=time.monotonic):
    """Run `spec` (a validated exec spec) with the private key `key_pem` (bytes). Returns {"exit_code": int|None,
    "stdout", "stderr", "truncated", "label": str|None, "duration_ms"}. Never raises: a failure is a label.
    `mask(text)` hides credential values in the output; `known_hosts_lines` are the pinned lines for this host
    and port (sshkey.known_host_lines); nothing is connected to when there are none."""
    t0 = clock()
    res = {"exit_code": None, "stdout": "", "stderr": "", "truncated": False, "label": None, "duration_ms": 0}

    def done(label=None, **kw):
        res.update(kw)
        res["label"] = label
        res["duration_ms"] = int((clock() - t0) * 1000)
        return res

    if not known_hosts_lines:
        return done("host_not_pinned")
    ssh, agent_bin, add_bin = (_binary(cfg, n) for n in ("ssh", "ssh-agent", "ssh-add"))
    if not (ssh and agent_bin and add_bin):
        return done("ssh_unavailable")
    workdir, agent, proc = None, None, None
    try:
        try:
            base = workdir_base
            if base:
                os.makedirs(base, mode=0o700, exist_ok=True)
            workdir = tempfile.mkdtemp(prefix="x-", dir=base)
            if len(os.path.join(workdir, "a")) > _SOCK_MAX:           # a unix socket path has a hard limit
                shutil.rmtree(workdir, ignore_errors=True)
                workdir = tempfile.mkdtemp(prefix="asbx-")
            os.chmod(workdir, 0o700)
            sock, known = os.path.join(workdir, "a"), os.path.join(workdir, "known_hosts")
            fd = os.open(known, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(known_hosts_lines) + "\n")
            env = _minimal_env(workdir)
            agent = _start_agent(agent_bin, sock, env)
            with open(os.path.join(workdir, "agent.pid"), "w") as f:     # so a start-up sweep can end it after a crash
                f.write(str(agent.pid))
            add = subprocess.run([add_bin, "-"], input=key_pem, env={**env, "SSH_AUTH_SOCK": sock},
                                 capture_output=True, timeout=10)
            if add.returncode != 0:
                return done("internal")
        except FileNotFoundError:
            return done("ssh_unavailable")
        except (OSError, subprocess.SubprocessError, RuntimeError):
            return done("internal")

        command, stdin = execmode.remote_payload(spec)
        argv = ([ssh] + [o.format(known_hosts=known) for o in FIXED_OPTIONS]
                + ["-l", spec["user"], "-p", str(spec["port"]), "--", spec["host"], command])
        try:
            proc = popen(argv, env={**env, "SSH_AUTH_SOCK": sock},
                         stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            return done("ssh_unavailable")
        except OSError:
            return done("internal")
        state = {"timeout": False, "cap": False}

        def kill(why):
            if proc.poll() is not None:                 # already over: a late timer must not relabel a finished run
                return
            state[why] = True
            try:
                proc.kill()
            except OSError:
                pass
        cap = cfg["max_output_bytes"]
        out = _Capped(proc.stdout, cap, lambda: kill("cap"))
        err = _Capped(proc.stderr, cap, lambda: kill("cap"))
        timer = timer_cls(spec["timeout_s"], lambda: kill("timeout"))
        timer.daemon = True
        timer.start()
        try:
            if stdin is not None:
                try:
                    proc.stdin.write(stdin)
                    proc.stdin.close()
                except OSError:
                    pass                                    # ssh ended before reading it all: its exit says why
            proc.wait()
            out.thread.join()
            err.thread.join()
        finally:
            timer.cancel()
        rc = proc.returncode
        so = bytes(out.buf).decode("utf-8", "replace")
        se = bytes(err.buf).decode("utf-8", "replace")
        truncated = out.over or err.over
        if state["timeout"]:
            return done("timeout", stdout=mask(so), stderr=mask(se), truncated=truncated)
        if state["cap"]:
            return done("output_cap", stdout=mask(so), stderr=mask(se), truncated=True)
        if rc == 255:
            label = classify_ssh_failure(se)
            if label:                                       # ssh itself failed: its words are not the agent's to read
                return done(label)
        return done(None, exit_code=rc, stdout=mask(so), stderr=mask(se), truncated=truncated)
    except Exception:  # noqa: BLE001 -- the call must always settle; a fixed label only
        return done("internal")
    finally:
        if proc is not None:
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(5)
                except (OSError, subprocess.SubprocessError):
                    pass
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if pipe is not None:
                        pipe.close()
                except OSError:
                    pass
        if agent is not None:
            _stop(agent)
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)

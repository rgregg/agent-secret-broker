"""execmode: the pure part of request mode `exec` (grammar, classification, config, payloads).

The properties: a command is "simple" only under a tiny grammar (every shell metacharacter
makes it not simple); only a simple command on the read-only table is rated low without a
model, and a flag outside the entry's set takes it off the table; the text the remote shell
receives is the text that was classified (`rebuild` round-trips); a script travels on stdin.
"""
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import execmode  # noqa: E402

META = list(";&|<>()$`\\\n*?[]{}~!#")        # the design's list of unquoted characters
CFG = execmode.parse_config({"enabled": True, "clients": ["c-1a2b3c4d"]})


def spec(**kw):
    s = {"host": "nas.example.com", "user": "ryan", **kw}
    if "script" not in kw:
        s.setdefault("command", "uptime")
    return s


def valid(**kw):
    s = spec(**kw)
    execmode.validate(s, CFG)
    return s


class Grammar(unittest.TestCase):
    def test_plain_command_is_simple(self):               # positive control for the table below
        self.assertEqual(execmode.parse_simple("systemctl status nginx"), ["systemctl", "status", "nginx"])

    def test_every_metacharacter_makes_it_not_simple(self):
        for ch in META:
            with self.subTest(ch=repr(ch)):
                self.assertIsNone(execmode.parse_simple(f"ls a{ch}b"), ch)
                self.assertIsNone(execmode.parse_simple(f"ls {ch}"), ch)

    NON_POSIX = "\\\n!"       # read differently inside quotes by fish, csh or tcsh: such a word is not simple

    def test_metacharacters_inside_single_quotes_are_literal(self):
        for ch in META:
            if ch in self.NON_POSIX:
                continue
            with self.subTest(ch=repr(ch)):
                self.assertEqual(execmode.parse_simple(f"echo 'a{ch}b'"), ["echo", f"a{ch}b"])

    def test_a_backslash_newline_or_bang_in_any_word_is_not_simple_however_it_is_quoted(self):
        for ch in self.NON_POSIX:
            for text in (f"echo 'a{ch}b'", f'echo "a{ch}b"', f"echo a{ch}b", f"echo 'x' 'a{ch}'"):
                with self.subTest(text=text):
                    self.assertIsNone(execmode.parse_simple(text))
            self.assertIsNone(execmode.classify(valid(command=f"uptime 'a{ch}b'"), CFG)["level"])
        self.assertEqual(execmode.parse_simple("echo 'a b' \"c;d\""), ["echo", "a b", "c;d"])     # control

    def test_dollar_backtick_backslash_inside_double_quotes_are_not_simple(self):
        for ch in "$`\\":
            with self.subTest(ch=ch):
                self.assertIsNone(execmode.parse_simple(f'echo "a{ch}b"'))
        self.assertEqual(execmode.parse_simple('echo "a b; c|d"'), ["echo", "a b; c|d"])   # control

    def test_unterminated_quote_and_empty_and_tab_are_not_simple(self):
        for text in ("echo 'abc", 'echo "abc', "", "   ", "ls\t-l", "ls\r"):
            self.assertIsNone(execmode.parse_simple(text), repr(text))

    def test_variable_assignment_prefix_is_not_simple(self):
        # `LD_PRELOAD=x ls` runs ls with an environment the argv view would not show
        self.assertIsNone(execmode.parse_simple("FOO=bar ls"))
        self.assertEqual(execmode.parse_simple("ls FOO=bar"), ["ls", "FOO=bar"])        # control

    def test_adjacent_quoted_pieces_join_into_one_word(self):
        self.assertEqual(execmode.parse_simple("echo a'b c'\"d\"''"), ["echo", "ab cd"])
        self.assertEqual(execmode.parse_simple("echo ''"), ["echo", ""])

    def test_rebuild_round_trips(self):
        cases = [["ls"], ["echo", "a b", "c'd", 'e"f', "", "x;y", "$HOME", "~", "*", "é", "-n"],
                 ["systemctl", "status", "nginx.service"], ["echo", "%+@:,./=-_"]]
        for argv in cases:
            with self.subTest(argv=argv):
                self.assertEqual(execmode.parse_simple(execmode.rebuild(argv)), argv)

    def test_a_real_shell_reads_the_rebuilt_command_as_exactly_the_parsed_argv(self):
        """The remote shell must see what the card showed. Every word over a hostile alphabet goes through a real
        sh: `printf '%s\\0' <rebuilt>` must print back exactly the words that were parsed."""
        import itertools
        import shutil
        import subprocess
        sh = shutil.which("sh")
        if sh is None:
            self.skipTest("no sh on this machine")
        alphabet = ["a", " ", "'", '"', "\\", "$", "`", ";", "\u00e9", "\n", "-", "~", "*", "#", "=", "!", "(", "&"]
        words = ["".join(w) for n in (1, 2, 3) for w in itertools.product(alphabet, repeat=n)]
        self.assertGreater(len(words), 5000)
        lines, want = [], []
        for w in words:
            lines.append("printf '%s\\0' " + execmode.rebuild(["echo", w]))
            want.append(w)
        out = subprocess.run([sh], input="\n".join(lines).encode(), capture_output=True, check=True).stdout.decode()
        got = out.split("\0")[:-1]
        self.assertEqual(got[0::2], ["echo"] * len(words))      # positive control: every line ran and printed
        self.assertEqual(got[1::2], want)

    def test_a_real_shell_reads_anything_the_grammar_calls_simple_as_the_parsed_argv(self):
        """The grammar must be a true subset of shell: for every short text over a hostile alphabet that
        parse_simple accepts, `printf '%s\\0' <text>` in a real sh prints exactly the parsed words."""
        import itertools
        import shutil
        import subprocess
        sh = shutil.which("sh")
        if sh is None:
            self.skipTest("no sh on this machine")
        alphabet = ["a", " ", "'", '"', "-", "=", "~", "{", "}", "%", "@", ":", "/", ".", ",", "+", "_", "\u00e9"]
        texts = []
        for n in range(1, 5):
            for w in itertools.product(alphabet, repeat=n):
                text = "".join(w)
                argv = execmode.parse_simple(text)
                if argv is not None:
                    texts.append((text, argv))
        self.assertGreater(len(texts), 20000)
        script = "\n".join("printf '%s\\0' x " + text for text, _ in texts)
        out = subprocess.run([sh], input=script.encode(), capture_output=True, check=True).stdout.decode()
        got = out.split("\0")[:-1]
        want = [w for _, argv in texts for w in ["x"] + argv]
        self.assertEqual(got, want)

    def test_rebuild_quotes_the_dangerous_words(self):
        out = execmode.rebuild(["echo", "a b", "x;y", "$HOME", "plain"])
        self.assertEqual(out, "echo 'a b' 'x;y' '$HOME' plain")


class Review(unittest.TestCase):
    """Findings of the branch review: scrubbing outside the model, option-looking first words, zsh word starts."""

    def test_audit_and_push_never_carry_obvious_secrets(self):
        for cmd, secret in (("mysql -u root --password hunter2xyz db", "hunter2xyz"),
                            ("curl -H 'Authorization: Bearer abcd1234efgh5678' http://x/", "abcd1234efgh5678"),
                            ("deploy --token=tok_live_12345 now", "tok_live_12345"),
                            ("echo " + "A" * 40, "A" * 40)):
            s = valid(command=cmd)
            self.assertNotIn(secret, json.dumps(execmode.audit_fields(s)), cmd)
            self.assertNotIn(secret, execmode.push_text(s), cmd)
            self.assertIn(secret, execmode.display_text(s), cmd)          # the human's card still shows it all
        a = execmode.audit_fields(valid(command="ls -la /var/log"))          # control: ordinary text is kept
        self.assertEqual(a["argv"], ["ls", "-la", "/var/log"])

    def test_the_model_text_scrubs_a_bearer_token(self):
        s = valid(command="curl -H 'Authorization: Bearer abcd1234efgh5678' http://x/")
        self.assertNotIn("abcd1234efgh5678", execmode.model_text(s))
        self.assertIn("curl", execmode.model_text(s))

    def test_audit_keeps_a_newline_visible(self):
        a = execmode.audit_fields(valid(command="uptime\nrm -rf /srv"))
        self.assertNotEqual(a["argv"], ["uptime", "rm", "-rf", "/srv"])
        self.assertTrue(any("<U+000A>" in w for w in a["argv"]))

    def test_a_first_word_that_looks_like_an_option_is_sent_quoted(self):
        for typed in ("'-A'", "'-oFoo=bar' x", "'-F/tmp/x'"):
            payload = execmode.remote_payload(valid(command=typed))[0]
            self.assertFalse(payload.startswith("-"), payload)
            self.assertEqual(execmode.parse_simple(payload), execmode.parse_simple(typed))
        self.assertEqual(execmode.remote_payload(valid(command="ls -la"))[0], "ls -la")     # later words stay bare

    def test_words_starting_with_zsh_expanders_are_quoted(self):
        for w in ("=ls", "%1", "~"):
            out = execmode.rebuild(["echo", w])
            self.assertEqual(out, f"echo '{w}'")
        self.assertEqual(execmode.rebuild(["echo", "a=b", "x%y"]), "echo a=b x%y")


class Table(unittest.TestCase):
    def low(self, text):
        return execmode.classify(valid(command=text), CFG)["level"]

    def test_allowed(self):
        for text in ("systemctl status nginx", "systemctl is-active nginx.service", "docker ps -a", "docker version",
                     "df -h",
                     "uptime", "free -h", "uname -a", "hostname", "date +%s", "ls -la /var/log",
                     "ps", "ps -o pid,comm", "ps -eo pid,ppid,comm,etime,stat,%cpu,%mem,user", "ip addr show", "ip -4 addr", "ip route", "ss -tlnp",
                     "zpool status -v", "zfs list -t snapshot", "/usr/bin/systemctl status nginx"):
            with self.subTest(text=text):
                c = execmode.classify(valid(command=text), CFG)
                self.assertEqual(c["level"], "low", c)
                self.assertEqual(c["argv"], execmode.parse_simple(text))
                self.assertTrue(c["reason"])

    def test_not_allowed(self):
        for text in ("systemctl restart nginx", "systemctl edit nginx", "systemctl status --host=x nginx",
                     "systemctl -H root@other status nginx", "docker exec web sh", "docker run x",
                     "docker logs -f web", "docker logs --follow web", "journalctl -f", "journalctl --vacuum-size=1M",
                     "cat /etc/passwd", "rm -rf /", "hostname newname", "date 010112002020", "date -s x",
                     "free -s 1", "ip addr add 10.0.0.1/24 dev eth0", "ip link set eth0 down",
                     "zpool destroy tank", "zfs destroy tank/x", "ss -K", "ls --color=always x/../..;x",
                     "/tmp/systemctl status x", "/usr/bin/../../tmp/systemctl status x", "./systemctl status x",
                     "systemctl", "docker", "systemctl status -x", "docker ps --format {{.ID}}", "ls -la; id",
                     "uptime | sh", "ls $(id)",
                     # entries that print environment or config (secrets): the model decides, not the table
                     "docker inspect web", "systemctl show nginx", "systemctl show", "ps e", "ps aux e", "ps eww", "ps aux", "ps -ef", "ps -e", "ps -A", "ps -eo pid,args", "ps -o pid,cmd", "ps -eo pid,command",
                     "ps -o pid,comm,args", "ps aux pid", "ps -ef pid", "ps -e pid", "ps -eo", "ps -o", "ps -eo pid,comm e", "ps -ef -o pid",
                     "docker ps --no-trunc", "docker ps -a --no-trunc", "systemctl status --full nginx",
                     "systemctl status -l nginx", "systemctl status -n 500 nginx", "systemctl status --lines=51 nginx",
                     "systemctl status --lines=1000 nginx", "systemctl status -n 5 nginx",
                     "ps -eo pid,args", "ps axe", "docker info", "docker logs web", "docker logs --tail=100 web",
                     "journalctl -u nginx -n 50 --no-pager", "journalctl --no-pager"):
            with self.subTest(text=text):
                self.assertIsNone(self.low(text))

    def test_a_script_is_never_low(self):
        s = {"host": "h.example.com", "user": "u", "script": {"text": "uptime", "interpreter": "sh"}}
        execmode.validate(s, CFG)
        c = execmode.classify(s, CFG)
        self.assertIsNone(c["level"])
        self.assertIsNone(c["argv"])
        self.assertEqual(self.low("uptime"), "low")             # control: the same text as a command is low

    def test_non_simple_command_of_allowed_program_is_not_low(self):
        for ch in META:
            if ch == "\n":
                continue
            with self.subTest(ch=repr(ch)):
                self.assertIsNone(self.low(f"uptime {ch}"))
        self.assertEqual(self.low("uptime"), "low")

    def test_environment_dumpers_are_not_low_but_their_siblings_are(self):
        for text in ("systemctl status nginx", "docker ps", "docker images", "ps"):         # positive control
            self.assertEqual(self.low(text), "low", text)
        for text in ("docker inspect web", "systemctl show nginx", "ps e", "ps aux e"):
            self.assertIsNone(self.low(text), text)

    def test_commands_that_print_other_processes_arguments_are_not_low_but_safe_forms_are(self):
        for text in ("ps", "ps -o pid,comm", "ps -eo pid,ppid,comm,etime,stat,%cpu,%mem,user", "docker ps", "docker ps -a",
                     "systemctl status nginx", "systemctl status --lines=50 nginx", "systemctl status --lines=5 nginx"):
            self.assertEqual(self.low(text), "low", text)             # positive controls
        for text in ("ps aux", "ps -ef", "ps -eo pid,args", "docker ps --no-trunc", "systemctl status --lines=51 nginx",
                     "systemctl status -n 100 nginx", "systemctl status --full nginx"):
            self.assertIsNone(self.low(text), text)

    def test_readonly_extension(self):
        cfg = execmode.parse_config({"readonly": ["smartctl -a", "systemctl list-sockets"]})
        ok = lambda t: execmode.classify(valid(command=t), cfg)["level"]            # noqa: E731
        self.assertEqual(ok("smartctl -a /dev/sda"), "low")
        self.assertEqual(ok("systemctl list-sockets"), "low")
        self.assertIsNone(ok("systemctl restart x"))
        self.assertIsNone(execmode.classify(valid(command="smartctl -a /dev/sda"), CFG)["level"])   # default table lacks it
        self.assertIsNone(ok("smartctl -a; id"))

    def test_readonly_extension_allows_only_the_flags_the_owner_lists(self):
        cfg = execmode.parse_config({"readonly": ["smartctl -a --health", "lsblk"]})
        ok = lambda t: execmode.classify(valid(command=t), cfg)["level"]            # noqa: E731
        self.assertEqual(ok("smartctl -a /dev/sda"), "low")                         # listed flag, positional
        self.assertEqual(ok("smartctl --health -a /dev/sda"), "low")
        self.assertEqual(ok("lsblk"), "low")
        for text in ("smartctl -s on /dev/sda", "smartctl --xall /dev/sda", "smartctl -a --scan",
                     "smartctl -aX /dev/sda", "lsblk -f", "lsblk --json", "smartctl -a --health=x /dev/sda"):
            self.assertIsNone(ok(text), text)

    def test_readonly_extension_flags_must_be_plain(self):
        for bad in ("smartctl -a;b", "smartctl -", "smartctl --", "smartctl -a=b", "smartctl -a x", "-a smartctl",
                    "smartctl " + " ".join(f"-f{i}" for i in range(11))):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                execmode.parse_config({"readonly": [bad]})

    def test_readonly_extension_cannot_name_a_shell_character(self):
        for bad in ("a;b", "a b|c", "$x", "a`b`", "-x", "", "a\nb", "x" * 200, "../x", "a b c d", 5, "ls &"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                execmode.parse_config({"readonly": [bad]})
        execmode.parse_config({"readonly": ["smartctl"]})                          # control


class Validate(unittest.TestCase):
    def bad(self, msg_part, **kw):
        s = spec(**kw)
        with self.assertRaises(ValueError) as cm:
            execmode.validate(s, CFG)
        self.assertIn(msg_part, str(cm.exception))
        return str(cm.exception)

    def test_normalizes(self):
        s = valid(command="ls", host="NAS.Example.COM")
        self.assertEqual(s, {"host": "nas.example.com", "user": "ryan", "port": 22, "command": "ls",
                             "timeout_s": 60})
        s = valid(script={"text": "id\n"}, port=2222, timeout_s=5)
        self.assertEqual(s["script"], {"text": "id\n", "interpreter": "sh"})
        self.assertEqual((s["port"], s["timeout_s"]), (2222, 5))
        self.assertNotIn("command", s)

    def test_command_or_script_exactly_one(self):
        self.bad("exactly one", command="ls", script={"text": "x"})
        self.bad("exactly one", command=None, script=None)

    def test_control_and_hidden_characters(self):
        for c in ("a\x00b", "a\x07b", "a\x1bb", "a\rb", "a\x7fb"):
            self.bad("control character", command=c)
        self.bad("hidden characters", command="ls ‮txt")       # bidi override
        self.bad("hidden characters", command="ls ​")           # zero width
        self.bad("hidden characters", script={"text": "x‮"})
        valid(command="echo a\tb\nc")                                 # tab and newline are legal

    def test_lengths(self):
        valid(command="x" * 4096)
        self.bad("longer", command="x" * 4097)
        valid(script={"text": "x" * 32768})
        self.bad("longer", script={"text": "x" * 32769})
        self.bad("longer", script={"text": "é" * 16385})              # bytes, not characters

    def test_command_must_not_start_with_dash(self):
        # a leading dash after the host could be parsed as an ssh option by an old client
        self.bad("must not start", command="-oProxyCommand=x")
        self.bad("must not start", command="  -x")
        valid(command="ls -l")

    def test_host(self):
        for h in ("-oProxyCommand=x", "a b", "a;b", "", "nas.", ".nas", "a..b", "x" * 254, 5, None, "a@b", "[::1]"):
            self.bad("host", host=h)
        valid(host="127.0.0.1")
        valid(host="a-b.example.com")

    def test_user(self):
        for u in ("-oProxyCommand=x", "a b", "", "x" * 65, 5, None, "a\nb", "é"):
            self.bad("user", user=u)
        valid(user="ryan")
        valid(user="deploy.bot-1")

    def test_port(self):
        for p in (0, 65536, -1, "22", True, 22.0, None):
            if p is None:
                continue
            self.bad("port", port=p)
        self.assertEqual(valid(port=1)["port"], 1)
        self.assertEqual(valid(port=65535)["port"], 65535)

    def test_timeout(self):
        for t in (0, -1, 601, "5", True, 1.5):
            self.bad("timeout_s", timeout_s=t)
        self.assertEqual(valid(timeout_s=600)["timeout_s"], 600)
        small = execmode.parse_config({"max_seconds": 30})
        s = spec(timeout_s=31)
        with self.assertRaises(ValueError):
            execmode.validate(s, small)
        s = spec(timeout_s=30)
        execmode.validate(s, small)

    def test_default_timeout_is_capped_by_max_seconds(self):
        small = execmode.parse_config({"max_seconds": 20})
        s = spec()
        execmode.validate(s, small)
        self.assertEqual(s["timeout_s"], 20)

    def test_script_fields(self):
        self.bad("interpreter", script={"text": "x", "interpreter": "python"})
        self.bad("script", script="echo hi")
        self.bad("script", script={"text": ""})
        self.bad("script", script={"text": 5})
        self.bad("script", script={"text": "x", "extra": 1})
        self.assertEqual(valid(script={"text": "x", "interpreter": "bash"})["script"]["interpreter"], "bash")

    def test_unknown_field_refused(self):
        self.bad("unknown field", ssh_options=["-oProxyCommand=x"])
        self.bad("unknown field", env={"A": "b"})

    def test_message_never_repeats_the_command(self):
        for kw in ({"command": "S3CR3T-canary \x00"}, {"command": "S3CR3T-" + "x" * 5000}, {"host": "S3CR3T-canary host"},
                   {"user": "S3CR3T canary"}):
            with self.assertRaises(ValueError) as cm:
                execmode.validate(spec(**kw), CFG)
            self.assertNotIn("S3CR3T", str(cm.exception))


class Config(unittest.TestCase):
    def test_defaults(self):
        c = execmode.parse_config(None)
        self.assertEqual(c, {"enabled": False, "clients": [], "max_concurrent": 4, "max_output_bytes": 262144,
                             "max_seconds": 600, "max_pending_per_client": 3, "readonly": [], "ssh_path": None,
                             "probe_per_client": 30, "probe_overall": 120})
        self.assertEqual(execmode.parse_config({}), c)

    def test_values(self):
        c = execmode.parse_config({"enabled": True, "clients": ["c-1a2b3c4d", "c-1a2b3c4d"], "max_concurrent": 2,
                                   "ssh_path": "/opt/fake", "readonly": ["uptime", "uptime"]})
        self.assertEqual((c["enabled"], c["clients"], c["max_concurrent"], c["ssh_path"], c["readonly"]),
                         (True, ["c-1a2b3c4d"], 2, "/opt/fake", ["uptime"]))

    def test_bad(self):
        for raw in ({"bogus": 1}, {"enabled": "yes"}, {"clients": "c-1a2b3c4d"}, {"clients": ["nope"]},
                    {"max_concurrent": 0}, {"max_concurrent": 33}, {"max_concurrent": True},
                    {"max_output_bytes": 10}, {"max_output_bytes": 10 ** 9}, {"max_seconds": 0},
                    {"max_seconds": 601}, {"max_pending_per_client": 0}, {"readonly": "ls"},
                    {"ssh_path": "relative/dir"}, {"ssh_path": 5}, {"probe_per_client": 0}, {"probe_per_client": 1001},
                    {"probe_overall": 0}, {"probe_overall": True}, "x", [], 5):
            with self.subTest(raw=raw), self.assertRaises(ValueError) as cm:
                execmode.parse_config(raw)
            self.assertIn("exec", str(cm.exception))

    def test_check_allowed(self):
        client = {"id": "c-1a2b3c4d"}
        execmode.check_allowed(CFG, client)                                       # positive control
        with self.assertRaises(PermissionError):
            execmode.check_allowed(CFG, {"id": "c-00000000"})
        with self.assertRaises(PermissionError):
            execmode.check_allowed(CFG, {"id": "c-1a2b3c4d", "legacy": True})     # listed id, legacy key
        with self.assertRaises(PermissionError):
            execmode.check_allowed(CFG, None)
        off = execmode.parse_config({"enabled": False, "clients": ["c-1a2b3c4d"]})
        with self.assertRaises(PermissionError) as cm:
            execmode.check_allowed(off, client)
        self.assertIn("disabled", str(cm.exception))


class Payload(unittest.TestCase):
    def test_simple_is_rebuilt(self):
        s = valid(command="echo   'a b'  \"c\"")
        self.assertEqual(execmode.remote_payload(s), ("echo 'a b' c", None))

    def test_simple_lookalike_is_sent_verbatim_bytes(self):
        s = valid(command="ls /tmp/аbc")        # cyrillic a
        cmd, stdin = execmode.remote_payload(s)
        self.assertEqual(cmd.encode(), "ls '/tmp/аbc'".encode())
        self.assertNotEqual(cmd.encode(), b"ls '/tmp/abc'")
        self.assertIsNone(stdin)

    def test_non_simple_is_byte_for_byte(self):
        text = "ls /tmp | grep 'a'  ; echo $HOME\n"
        s = valid(command=text)
        self.assertEqual(execmode.remote_payload(s), (text, None))

    def test_script(self):
        s = valid(script={"text": "set -e\necho hi\n", "interpreter": "bash"})
        self.assertEqual(execmode.remote_payload(s), ("bash -s", b"set -e\necho hi\n"))
        self.assertEqual(execmode.script_sha256(s), hashlib.sha256(b"set -e\necho hi\n").hexdigest())

    def test_script_sha_is_none_for_a_command(self):
        self.assertIsNone(execmode.script_sha256(valid(command="ls")))


class Display(unittest.TestCase):
    def test_display_shows_what_runs_with_non_ascii_visible(self):
        s = valid(command="ls /tmp/аbc 'a b'")
        self.assertEqual(execmode.display_text(s), "ls '/tmp/<U+0430>bc' 'a b'")

    def test_display_makes_newline_and_tab_visible(self):
        s = valid(command="echo 'a\nb\tc'")
        self.assertEqual(execmode.display_text(s), "echo 'a<U+000A>b<U+0009>c'")

    def test_display_of_script_names_the_hash_not_the_text(self):
        s = valid(script={"text": "echo S3CR3T-body"})
        d = execmode.display_text(s)
        self.assertIn(execmode.script_sha256(s), d)
        self.assertNotIn("S3CR3T-body", d)

    def test_push_text(self):
        s = valid(command="uptime")
        self.assertEqual(execmode.push_text(s), "run on nas.example.com as ryan: uptime")
        s = valid(command="echo " + "x" * 500)
        self.assertLessEqual(len(execmode.push_text(s)), 260)
        s = valid(script={"text": "echo S3CR3T-body"})
        self.assertNotIn("S3CR3T-body", execmode.push_text(s))
        self.assertIn("script", execmode.push_text(s))

    def test_audit_fields_command(self):
        long = "/" + "ab/" * 140
        words = long + " " + " ".join(f"w{i}" for i in range(80))
        s = valid(command="echo " + words)
        a = execmode.audit_fields(s)
        self.assertEqual(len(a["argv"]), 50)
        self.assertEqual(max(len(w) for w in a["argv"]), 300)             # the long word was clipped
        self.assertEqual(a["argv"][:2], ["echo", long[:300]])
        self.assertEqual((a["host"], a["account"], a["port"], a["timeout_s"]), ("nas.example.com", "ryan", 22, 60))
        self.assertNotIn("script_digest", a)

    def test_audit_fields_script_has_hash_and_length_only(self):
        s = valid(script={"text": "echo S3CR3T-body\n"})
        a = execmode.audit_fields(s)
        self.assertEqual(a["script_digest"], hashlib.sha256(b"echo S3CR3T-body\n").hexdigest())
        self.assertEqual(a["script_len"], 17)
        self.assertNotIn("S3CR3T", repr(a))
        self.assertNotIn("argv", a)


if __name__ == "__main__":
    unittest.main()

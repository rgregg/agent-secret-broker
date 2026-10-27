# Running commands as root with approval (`asb sudo`, `asb-root-exec`)

An agent that needs root runs `asb sudo -- COMMAND ARGS...`. A small compiled helper, `asb-root-exec`,
asks the broker; you read the exact command on your phone; only if you approve does the helper run it.
No account password exists anywhere. The design and what it does not protect against are in
[proposals/root-exec.md](proposals/root-exec.md); the broker's side (request mode `sudo`) is in
[reference.md](reference.md#root-commands-request-mode-sudo-proposal-docsproposalsroot-execmd).

## How it fits together

    agent --> asb sudo -- CMD...
                 `--> sudo -n /usr/local/sbin/asb-root-exec -- CMD...     (the one passwordless sudoers rule)
                          `--> broker (its own enrolled client key, readable only by root)
                                 you approve the exact command on the approval page
                          `--> exec CMD as root: clean environment, fixed PATH, no shell

The helper asks the broker itself, with a key the agent cannot read, so the agent cannot approve its
own request or replay an old one. If the broker is down, denies, or does not answer in time, nothing runs.

## Install (once per machine, as root)

1. **Build and install the helper.** Needs a Rust toolchain.

       cargo build --release --locked -p asb-root-exec
       sudo install -o root -g root -m 0755 target/release/asb-root-exec /usr/local/sbin/asb-root-exec

   `/usr/local`, `/usr/local/sbin` and every directory above must be owned by root and not writable by
   group or others (the defaults on a normal system). The helper checks this about itself at every start
   and refuses to run otherwise.

2. **Give the helper its own broker client.** Run `asb enroll` as root (it uses root's config, not
   yours), approve it in the broker's Clients tab, then copy the result:

       sudo asb enroll --name "$(hostname)-root-exec"
       sudo install -d -o root -g root -m 0755 /etc/secret-broker
       sudo install -o root -g root -m 0600 /root/.config/secret-broker/client.json /etc/secret-broker/root-exec.json

   The file must be mode 0600 and owned by root, or the helper refuses to read it.

   **Then say which programs it may run.** Out of the box it runs **nothing**: with no policy keys the
   allow-list is empty. Add `mode` and `allow` to the same file (root edits it; the agent cannot):

       sudo python3 - <<'PY'
       import json
       p = "/etc/secret-broker/root-exec.json"
       c = json.load(open(p))
       c["allow"] = ["/usr/bin/systemctl", "/usr/bin/journalctl", "/usr/bin/id"]
       json.dump(c, open(p, "w"), indent=2)
       PY

   `allow` is a list of absolute **real** paths: the file that actually runs. A command typed as `systemctl`
   or invoked through a symlink resolves to its real file first, and that file must be in the list exactly. An
   entry that is itself a symlink (or has `..` or `//` in it) makes the helper refuse to start and prints the real
   path to list instead (`/usr/bin/python3` is usually a link: list `readlink -f /usr/bin/python3`). This is on
   purpose: if a link were accepted it would silently allow whatever it points to, and for a multi-call program
   such as busybox or uutils `coreutils`, listing the link `id` would allow every applet, since they take the
   applet name from the first argument. Listing a multi-call binary allows all of its applets, so don't. An
   entry for a program that is not installed is kept and matches nothing. `"mode": "allowlist"` is the default.

   **To allow every program instead,** set `"mode": "allow_all"` (it must be written; there is no way to get it
   by omission, and a misspelled `mode` makes the helper refuse to run, not fall back). `allow` is then ignored.
   Only the allow-list is lifted: every check under "What the helper does and refuses" still applies (a program
   the agent could rewrite, the script rules, refusing wrappers, your approval for every command). Prefer an
   allow-list: with `allow_all`, each approval card is the only thing deciding what root may run.

3. **Allow it on the broker.** Note the new client's id (the Clients tab shows it, like `c-1a2b3c4d`) and add
   it to the broker's config (off by default; see reference.md):

       "sudo": { "enabled": true, "clients": ["c-1a2b3c4d"] }

   Only listed clients can make root requests; the agent's own client should **not** be listed.

4. **Add the one sudoers rule** (`sudo visudo -f /etc/sudoers.d/asb-root-exec`), naming your agent's user:

       ryan ALL=(root) NOPASSWD: /usr/local/sbin/asb-root-exec

   This is the only passwordless rule needed. Do not add `SETENV`, and do not allow arguments to be
   edited by wildcards: the helper takes the whole command after `--`.

5. **Try it.** With `/usr/bin/id` in `allow`, `asb sudo -- /usr/bin/id` should send a card to your phone;
   approve it and it prints `uid=0(root)...`; deny it and it exits 4. A program that is not allowed is refused
   at once (exit 10) without sending anything to your phone.

## What the helper does and refuses

- Runs only programs the admin allowed (`allow` in `/etc/secret-broker/root-exec.json`, or `"mode": "allow_all"`).
  The check is on the resolved real file and happens before the broker is asked, so a disallowed command never
  reaches your phone.
- Resolves the command's first word before asking, and shows you the **file that will actually run**:
  symlinks are followed first, so a link in a place the agent can write (`~/ls` pointing at `/bin/rm`)
  appears as `/bin/rm`, never as `ls`. That path is also the process's `argv[0]`, so multi-call binaries
  that choose their behaviour from the name they were started under (busybox applets) do not work through
  an alias; call the real binary. A bare name is
  looked up only in `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, never the caller's PATH.
- Refuses (exit 10, **without contacting the broker**) unless the file, and every directory above it, is
  owned by root and not writable by group or others. Running something the agent could rewrite as root
  would be a way around the approval, so a script in `~/bin` is refused by design.
- For an interpreter (`sh`, `bash`, `python3`, `perl`, `ruby`, `node`, `php`, ..., including versioned names such
  as `python3.11`) it allows exactly two forms and refuses everything else, before contacting the broker:
  - `INTERP SCRIPT [ARGS...]`: SCRIPT is the **first** argument (not an option) and an existing file owned by
    root, closed to group and other writes, with the same for every directory above it. The agent could
    otherwise rewrite it after you approved the card. You are shown, and the interpreter runs, SCRIPT's
    **resolved real path**, so a symlink cannot show one file and run another. Any later argument that names an
    existing file must be trusted the same way, and is shown and run as its resolved path: a runner such as
    python's `pdb` or `cProfile` executes its argument as code, so a file argument is not just data. To give a
    root command an agent-owned data file, copy it somewhere root owns first.
  - `INTERP -c CODE [ARGS...]` (or the interpreter's one exact inline flag: `-e` for perl and ruby, `-r` for php,
    ...): the code is in the command you read, and must be the very next word (one starting with `-` or `+` is
    refused: shells keep parsing options after `-c`). For shells and Python every word after the code is a plain
    argument. Perl, Ruby, Node, PHP and the like keep parsing switches after the code (`perl -e CODE -MEvil`), so
    for them any later word starting with `-` is refused.
  A lone `--version` or `--help` is allowed. Any other option before the script is refused (`-m`, `-r`, `-i`, `-s`,
  `--rcfile`, `-lc`, ...), as are `-` (also as the inline code), a missing file and an interpreter with no script:
  each of those loads or reads something the card does not show. This is a grammar, not an option parser, on purpose: parsing every
  interpreter's command line cannot be done reliably. Use `bash -c '...'` rather than `bash -lc '...'`.
- **Wrapper commands** (`env`, `nice`, `timeout`, `xargs`, `su`, `busybox`, `taskset`, `setpriv`, `systemd-run`,
  `ssh`, `gdb`, `valgrind`, ...) are refused: they start a command the helper cannot see. Run that command
  directly. The list is a denylist and cannot be complete: a launcher that is not on it is only as safe as its
  card.
- Looks again after you approve (the program and the script) and refuses if anything is no longer what you were
  shown.
- Runs the command with no shell, in the working directory it inherited (it never changes directory by
  path after you approve, so the directory you were shown cannot be swapped underneath it), and only `PATH`, `HOME=/root`, `USER`, `LOGNAME`,
  `LANG` and `TERM` (plus `SUDO_USER` for information). Nothing else of the caller's environment survives.
  `umask` is 022. It disables core dumps and ptrace of itself while it holds the broker key.

## Exit codes

The command's own, or: `2` usage, `3` broker unreachable or refused the request, `4` you denied it,
`5` it expired unanswered, `10` refused locally (not on the allow-list, unsafe file, config, directory or binary), `11` approved
but the command could not be started.

## Limits to know about

- You approve the **text** of a command. `bash -c '...'`, an editor, `make` or a package manager do more
  than their name says, so read those cards closely.
- With an allow-list, the programs that can run are the ones you chose, and the script rules below apply to any
  interpreter you allowed. Under `allow_all` there is no such choice, and the following limits matter more.
- The script check covers only programs it knows are interpreters. Anything else that can run other commands or
  read files (`find -exec`, `git`, `make`, editors, pagers, `awk -f`, `cp` of a file the agent can change) is as
  powerful as its text and is **not** checked: you approve names, not contents. What a trusted script itself runs,
  sources or imports is also its own business. Interpreters such as `python3` may load modules from the current
  directory, which the agent controls: run root commands from a directory only root can write to when that
  matters. Put anything root should run in a root-owned location.
- v1 runs as root only (no `-u USER`), has no interactive terminal handling beyond inheriting stdio, and
  never auto-approves: there is no "always" for a root command.
- Linux only.

## Testing it without trusting a real machine

`tests/e2e_root_exec/run.sh` builds a throwaway container (Debian, real root and sudo, an unprivileged `agent` user),
installs the helper root-owned with the one sudoers rule, starts the real broker in it, and drives the real `asb`
client as `agent`. The "phone" approves or denies through the approval page's HTTP endpoint. It checks, among other
things, that an approved command runs as uid 0, a denial runs nothing, a program not on the allow-list never reaches
the phone, the agent cannot read the helper's key or use sudo for anything else, and a script the agent wrote is
refused. Nothing on your machine changes: no host mounts, not privileged, no Docker socket, and the container is
removed afterwards. CI runs the same driver on a disposable runner. The driver edits `/etc` and creates a user, so
it refuses to start unless `ASB_E2E_DISPOSABLE=1`, which only the container and CI set.
It cannot test `systemctl` and other things that need systemd, which a container does not have.

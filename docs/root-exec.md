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

3. **Allow it on the broker.** Note the new client's id (the Clients tab shows it, like `c-1a2b3c4d`) and add
   it to the broker's config (off by default; see reference.md):

       "sudo": { "enabled": true, "clients": ["c-1a2b3c4d"] }

   Only listed clients can make root requests; the agent's own client should **not** be listed.

4. **Add the one sudoers rule** (`sudo visudo -f /etc/sudoers.d/asb-root-exec`), naming your agent's user:

       ryan ALL=(root) NOPASSWD: /usr/local/sbin/asb-root-exec

   This is the only passwordless rule needed. Do not add `SETENV`, and do not allow arguments to be
   edited by wildcards: the helper takes the whole command after `--`.

5. **Try it.** `asb sudo -- /usr/bin/id` should send a card to your phone; approve it and it prints
   `uid=0(root)...`; deny it and it exits 4.

## What the helper does and refuses

- Resolves the command's first word before asking, and shows you the **file that will actually run**:
  symlinks are followed first, so a link in a place the agent can write (`~/ls` pointing at `/bin/rm`)
  appears as `/bin/rm`, never as `ls`. That path is also the process's `argv[0]`, so multi-call binaries
  that choose their behaviour from the name they were started under (busybox applets) do not work through
  an alias; call the real binary. A bare name is
  looked up only in `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, never the caller's PATH.
- Refuses (exit 10, **without contacting the broker**) unless the file, and every directory above it, is
  owned by root and not writable by group or others. Running something the agent could rewrite as root
  would be a way around the approval, so a script in `~/bin` is refused by design.
- When the command is an interpreter (`sh`, `bash`, `python3`, `perl`, `ruby`, `node`, `php`, ...) or a wrapper
  that starts one (`env`, `nice`, `timeout`, `xargs`, ...), the first operand that is an existing file is the
  script it will run. That file, and every directory above it, must be owned by root and not writable by
  group or others, or the command is refused (exit 10, without contacting the broker). Otherwise the agent
  could rewrite the script after you approved the card. Inline code (`bash -c '...'`, `python3 -c '...'`) is
  in the command you read, so it needs no file. Only the first file operand is checked, so data files given to a
  trusted script are fine.
- Looks again after you approve (the program, and the script) and refuses if anything is no longer what you
  were shown.
- Runs the command with no shell, in the working directory it inherited (it never changes directory by
  path after you approve, so the directory you were shown cannot be swapped underneath it), and only `PATH`, `HOME=/root`, `USER`, `LOGNAME`,
  `LANG` and `TERM` (plus `SUDO_USER` for information). Nothing else of the caller's environment survives.
  `umask` is 022. It disables core dumps and ptrace of itself while it holds the broker key.

## Exit codes

The command's own, or: `2` usage, `3` broker unreachable or refused the request, `4` you denied it,
`5` it expired unanswered, `10` refused locally (unsafe file, config, directory or binary), `11` approved
but the command could not be started.

## Limits to know about

- You approve the **text** of a command. `bash -c '...'`, an editor, `make` or a package manager do more
  than their name says, so read those cards closely.
- The script check is a heuristic, not a parser of every interpreter's command line. It does not see:
  scripts named only by an option value the check mistakes for something else, `awk -f` and `sed -f` files,
  programs it does not know are interpreters, or what a script itself runs, sources or imports. Interpreters
  such as `python3` may also load modules from the current directory, which the agent controls: run root
  commands from a directory only root can write to when that matters. Put anything root should run in a
  root-owned location.
- v1 runs as root only (no `-u USER`), has no interactive terminal handling beyond inheriting stdio, and
  never auto-approves: there is no "always" for a root command.
- Linux only.

# End-to-end web-push rig (real Chrome on a real Mac)

Unit tests cannot tell whether a notification click reaches the service worker: that depends on Chrome and
macOS. This rig runs the real thing:

    throwaway broker (here)  --real web push via FCM-->  stock Chrome on a Mac  --real macOS banner-->  a real click
                                                          \--> what the worker saw (diag log, getNotifications, new tabs)

It found why clicking the approval notification did nothing in Chrome on macOS (see "Findings" below) and proves
the fix. It is **not** part of the CI suite (it needs a Mac); `python tests/run_tests.py` never touches it.

## One command

    ASB_E2E_SSH_OPTS="-o ControlPath=/tmp/cm -o ControlMaster=no" \
    python tools/e2e_push/rig.py run --ax-press --proof            # the shipped worker; expect worker_got_click true
    python tools/e2e_push/rig.py run --ax-press --variant regress_seen   # negative control: expect false
    python tools/e2e_push/rig.py run --ax-press --page-open        # a broker tab already open: it is focused
    python tools/e2e_push/rig.py down                              # stop everything it started

Results (JSON, screenshots) go to `/tmp/asb-e2e-out/<time>-<variant>/`. A run takes about a minute:

1. starts `testbroker.py` (file vault, real webpush notifier with fresh VAPID keys, identity header injected by
   a tiny proxy, `approve_base_url http://localhost:18931`) and `ssh -R` forwards it to the Mac, where
   `localhost` is a secure context, so no TLS or login is needed;
2. starts a **second, headed** Chrome on the Mac from `~/asb-e2e/Chrome E2E.app` (a re-signed copy with its own
   bundle id, `com.google.Chrome.e2e`, see "Why a copy") with a throwaway profile in `/tmp/asb-e2e-chrome-profile`
   and a loopback-only CDP port (`ssh -L`);
3. drives it with Playwright over CDP: opens `chrome://gcm-internals` (makes Chrome bring up its push
   connection reliably), loads the broker page, "Enable on this device" (a real FCM subscription), then
   triggers a request through the client API so the broker sends a real push; if FCM answers 410 for the
   brand-new registration it subscribes again;
4. optionally closes the broker tab (default) so the push arrives with no window, waits for the banner,
   finds it in the macOS accessibility tree **by its text** and presses it (`--ax-press`; never by screen
   position, other apps' banners are never touched), then reports whether the worker got `notificationclick`
   (its own diag ring, read over CDP) and whether a tab for the broker opened (CDP targets);
5. kills the test Chrome, the tunnels and the broker.

`--proof` also saves a crop of the banner (needs the VNC helper, see below) and a screenshot of the page the
click opened.

## What it needs

* This machine: Python 3.12 with `pip install playwright -r requirements.txt` (plus `asyncvnc pillow` for the VNC helper) (Playwright needs
  no browser download: it drives the Mac's Chrome), network to FCM, and an ssh login to the Mac. Set
  `ASB_E2E_MAC` (`user@host`, required) and `ASB_E2E_SSH_OPTS` (e.g. a ControlMaster socket so a
  broker-gated ssh agent asks once). Tunnels are added with `ssh -O forward` when a ControlPath is given,
  otherwise one background `ssh -N` is used.
* The Mac, once (a human at the screen; none of this can be done over ssh):
  1. System Settings > Privacy & Security > **Screen & System Audio Recording**: allow "ASB E2E Bridge";
  2. Privacy & Security > **Accessibility** (shown as "Device Control and Data Access"): allow "ASB E2E Bridge";
  3. Privacy & Security > **Automation**: "ASB E2E Bridge" may control "System Events" (click Allow when asked);
  4. System Settings > Notifications > **Chrome E2E**: Allow Notifications (and, for screen-shared sessions,
     "when mirroring or sharing the display": Allow Notifications);
  5. the console must be unlocked (a locked Mac shows the banner but cannot be clicked).
  "ASB E2E Bridge" is a stay-open AppleScript applet (`bridge.applescript`, installed by `mac_bridge.sh`): a
  command started over ssh has neither a window-server session nor those grants, so jobs are queued as files
  in `~/asb-e2e/q` and run by the applet (`.sh` as a child process for `screencapture`, `.scpt` inside the
  applet for UI scripting, because macOS checks Accessibility against the process that makes the call).
  **Never recompile the applet** (`--rebuild`): a new ad-hoc signature invalidates the grants.
* `vncd.py` / `vnc.py` are only for setting the grants up (Screen Sharing from here, driven by a script, with
  the login supplied through the secret broker) and for `--proof` crops. They are not needed to run the rig.

## Why a copy of Chrome

A second instance of the stock app shares its bundle id with the user's own Chrome, and macOS delivers a
notification response to **every** process with that bundle id. The copy (`mac_chrome_copy.sh`: `cp -R`,
change `CFBundleIdentifier`, ad-hoc `codesign`) makes notifications and clicks hermetic. It is launched with
`--use-mock-keychain --password-store=basic` so it never asks for the user's keychain. Nothing in the user's
Chrome or profile is read or changed.

## Experiments

* `rig.py run --variant NAME` re-runs the whole flow with an altered worker: `baseline`, `regress_seen`
  (the v13 behaviour: read the displayed list right after showing), `no_seen`, `no_sweep`, `none`,
  `require_interaction`, `no_actions`, `silent`, `minimal`, `no_renotify_no_timestamp`.
* `experiments.py [case ...]` shows notifications without a push (from the page, or from inside the worker)
  with several option sets and presses each by title; it is how the cause was narrowed down.

## Findings (Chrome 156.0.8078.47, macOS 27.0.1, 2026-10-25)

Symptom: the banner shows, a click does nothing, the worker never gets `notificationclick`, and
`getNotifications()` right after `showNotification()` is empty (`seen=0`).

* macOS does deliver the click: `usernoted` logs "Received response ... sent to NSUserNotification client
  com.google.Chrome.e2e" and Chrome's delegate responds (`didActivateNotification:`, delegateResponds 1).
* `registration.showNotification()` called from a **page** and clicked after a moment: worker gets the click.
* The same from **inside the worker** and any `getNotifications()` call issued at the same time or right
  after: the notification is not listed, and the click never reaches the worker.
* The same from the worker, but reading the list **3 s later**: listed, and the click is delivered.
* Through the real push: removing *both* reads (the `seen` probe that PR #37 added and the Approved-notice
  sweep that ran alongside the show) makes the click arrive and `clients.openWindow` open the broker tab;
  removing only one of them does not. With either read present, `seen=0` and no click.
* `requireInteraction: true` (Chrome's Alerts helper) does not help: macOS launches
  `Google Chrome Helper (Alerts)` for the response ("Failed to source application bundle") and nothing reaches
  the worker. `silent`, no `actions`, `data`, `renotify`, `timestamp`, tag, a broker tab open or not, the
  macOS Alerts style: none of them matter.
* `--disable-features=NativeNotifications` (Chrome draws its own toast) lists the notification at once.

Fix (service worker v14): never read the displayed list on Chromium after, or alongside, a
`showNotification()`. The sweep of earlier "Approved" notices now finishes first, then the request is shown,
and the `seen` probe is gone.

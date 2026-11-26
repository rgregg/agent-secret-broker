# ASBApprover

A macOS menu bar app (macOS 14 or later) that shows the broker's pending requests, posts a banner when
one needs you, and lets you approve or deny. It talks to the broker's approver API (`approver_api`,
see `docs/reference.md`, "Approver app API") and signs you in through your OpenID Connect provider.
The networking, sign-in and long-poll code is the `ASBApproverKit` package next to it.

**Anything running as you on this Mac can use this app to approve requests. Don't run agents on a
Mac where you approve.**

## Build locally

You need Xcode 15 or later and [XcodeGen](https://github.com/yonaskolb/XcodeGen). The Xcode project
is generated, not checked in.

    brew install xcodegen
    xcodegen --spec macos/ASBApprover/project.yml
    open macos/ASBApprover/ASBApprover.xcodeproj          # or build from the command line:
    xcodebuild -project macos/ASBApprover/ASBApprover.xcodeproj -scheme ASBApprover \
      -configuration Release -derivedDataPath macos/ASBApprover/build build

The app lands in `macos/ASBApprover/build/Build/Products/Release/ASBApprover.app`. Local builds are
signed ad hoc ("Sign to Run Locally"). To sign with your own team and bundle id:

    xcodebuild ... ASB_BUNDLE_ID=com.example.asb-approver DEVELOPMENT_TEAM=ABCDE12345

CI (`.github/workflows/macos.yml`, job `app`) builds the same way, signs with Developer ID and
notarizes when the `MACOS_SIGNING_CERT`, `MACOS_SIGNING_CERT_PASSWORD`, `MACOS_NOTARY_KEY`,
`MACOS_NOTARY_KEY_ID` and `MACOS_NOTARY_ISSUER` secrets are set, and uploads
`ASBApprover-macos.zip` as an artifact (and to the release on `v*` tags). A build without the
signing secrets is ad-hoc signed only: after downloading it, remove the quarantine flag
(`xattr -dr com.apple.quarantine ASBApprover.app`) or Gatekeeper refuses to open it.

## Configure the broker

1. At your identity provider, create a **public** OAuth2/OIDC client (no secret) for the app:
   authorization code with PKCE, redirect URI `asb-approver://callback`, JWT access tokens, and
   refresh tokens (`offline_access`). Limit it to you (and, optionally, a group).
2. Add `approver_api` to the broker config and restart it:

       "allowed_user": "you",
       "approver_api": {
         "issuer": "https://idp.example.com/application/o/asb-approver/",
         "client_id": "<client id>"
       }

   `docs/reference.md` lists the optional keys (`audience`, `username_claim`, `required_group`,
   `scopes`, `actions`).
3. Check it answers: `curl https://<broker client URL>/v1/approver/config` returns the issuer and
   client id.

## Use

1. Open the app; a lock appears in the menu bar. Click it, enter the broker's client URL (the one
   agents use, e.g. `https://broker.example:8800`) and choose **Sign in**. Sign in at your provider
   in the window that opens.
2. Allow notifications when macOS asks.
3. Optional: tick **Launch at login**.

The broker URL and the provider settings are kept in the app's preferences; the tokens only in the
Keychain. The app counts as "presence" (so the phone push can wait) only while its notifications
are allowed in System Settings, the screen is unlocked and you used the keyboard or mouse in the
last 2 minutes. With notifications turned off it tells the broker you are away once and stops
reporting presence until they are allowed again (checked when the app becomes active or its window
opens). Focus and Do Not Disturb are not visible to the app: with notifications allowed but
silenced by a Focus, you still count as present, so the phone push waits for the presence fallback.

## Manual verification

Run these on a Mac against a broker with `approver_api` configured (the home-lab broker for the
author). CI only proves the app builds.

1. **Sign in.** First run shows the warning text above verbatim and the URL field; sign-in opens
   the provider in a browser window and returns to the app; the popover then lists pending requests
   (or "Nothing is waiting for you").
2. **Banner approve.** From an agent, make a low-risk `asb http ...` request. A banner "Secret
   request [LOW]" / "<credential> from <client>" appears with Approve and Deny. Choose Approve on
   the banner: the agent gets its response and the row leaves the popover.
3. **Browser-only mode.** Start an `asb request-credential ...` request. Its row shows only Deny
   and "Open in browser" (which opens the approval page), and its banner has at most Deny.
4. **Decided elsewhere.** Approve or deny a pending request on the phone (or the dashboard): it
   disappears from the popover within a few seconds and its banner is removed, with no error.
5. **Presence.** With `notify_presence` configured and the Mac in use, a new request produces the
   Mac banner and no phone push until the presence fallback; lock the screen (Ctrl-Cmd-Q), make
   another request, and the phone push arrives at once.
6. **Plain text.** Make a request whose summary or URL contains Markdown, for example
   `**bold** [link](https://example.com)`: the popover shows the asterisks and brackets literally,
   with no link.

Also worth a look: "Always…" asks for confirmation first; "For…" lists the offered durations;
stopping the broker shows "Can't reach the broker. Retrying…" and the list recovers when it
returns; revoking the app's session at the provider shows "Sign in again".

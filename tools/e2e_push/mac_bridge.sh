#!/bin/sh
# Install (idempotent) and start the ASB E2E Bridge applet. Run ON the Mac (the rig does it over ssh).
set -e
D="$HOME/asb-e2e"; mkdir -p "$D/q"
APP="$D/ASB E2E Bridge.app"
if [ ! -d "$APP" ] || [ "$1" = "--rebuild" ]; then
  rm -rf "$APP"; osacompile -s -o "$APP" "$D/bridge.applescript"
fi
pgrep -f "ASB E2E Bridge.app" >/dev/null || open -g "$APP"

#!/bin/sh
# Make an isolated copy of Google Chrome with its own bundle id (com.google.Chrome.e2e) on the Mac.
# Why: a second instance of the stock app shares the bundle id with the user's running Chrome, and macOS
# routes notification responses by bundle id (to BOTH processes). The copy is re-signed ad hoc, lives in
# ~/asb-e2e and is deleted by cleanup. The user's Chrome is only read (copied), never modified.
set -e
D="$HOME/asb-e2e"; APP="$D/Chrome E2E.app"
[ -d "$APP" ] && [ "$1" != "--rebuild" ] && { echo "exists: $APP"; exit 0; }
rm -rf "$APP"
cp -R "/Applications/Google Chrome.app" "$APP"
P="$APP/Contents/Info.plist"
/usr/bin/plutil -replace CFBundleIdentifier -string com.google.Chrome.e2e "$P"
/usr/bin/plutil -replace CFBundleName -string "Chrome E2E" "$P"
/usr/bin/plutil -replace CFBundleDisplayName -string "Chrome E2E" "$P"
# Keystone/updater hooks off, then ad-hoc sign inside-out
/usr/bin/codesign --force --deep --sign - "$APP" 2>&1 | tail -3
echo built: $APP

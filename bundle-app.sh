#!/bin/bash
# Turns the GUI binary into a real macOS app, so you can start it from Finder
# or Spotlight instead of from a terminal.
#
# Usage:  ./bundle-app.sh          -> puts sshctl.app in target/
#         ./bundle-app.sh --install -> also copies it to /Applications
set -euo pipefail

cd "$(dirname "$0")"
APP="target/sshctl.app"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# CI hands in a prebuilt (universal) binary via BIN; without it, build one
# for this machine.
if [[ -n "${BIN:-}" ]]; then
  cp "$BIN" "$APP/Contents/MacOS/sshctl"
else
  cargo build --release --bin sshctl-gui
  cp target/release/sshctl-gui "$APP/Contents/MacOS/sshctl"
fi

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>              <string>sshctl</string>
  <key>CFBundleDisplayName</key>       <string>sshctl</string>
  <key>CFBundleIdentifier</key>        <string>io.github.ryge87.sshctl</string>
  <key>CFBundleVersion</key>           <string>0.1.0</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleExecutable</key>        <string>sshctl</string>
  <key>CFBundlePackageType</key>       <string>APPL</string>
  <key>LSMinimumSystemVersion</key>    <string>11.0</string>
  <!-- No suppressing of the Dock icon: this is an ordinary windowed program. -->
  <key>NSHighResolutionCapable</key>   <true/>
</dict>
</plist>
PLIST

# Without a signature Gatekeeper refuses the app the first time it is opened.
# An ad-hoc signature (-) is enough for personal use on this machine.
codesign --force --deep --sign - "$APP" 2>/dev/null || \
  echo "note: signing failed; open the app the first time via right-click > Open"

echo "done: $APP"

if [[ "${1:-}" == "--install" ]]; then
  rm -rf /Applications/sshctl.app
  cp -R "$APP" /Applications/
  echo "installed in /Applications/sshctl.app"
fi

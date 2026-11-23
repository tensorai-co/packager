#!/bin/bash
# Manual macOS checks that need a person: Finder's rendering of the .dmg window, and a real
# .pkg install with sudo. Results go to /tmp/packager-check (log, screenshot, Finder report).
#
#   scripts/manual-check-macos.sh build     # build the test app, .dmg and .pkg (no sudo)
#   scripts/manual-check-macos.sh finder    # open the .dmg in Finder, report layout, screenshot
#   scripts/manual-check-macos.sh install   # sudo installer -pkg …, then verify the install
#   scripts/manual-check-macos.sh cleanup   # remove the installed app and its receipt (sudo)
#   scripts/manual-check-macos.sh all       # all of the above, in order
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT=/tmp/packager-check
NAME="Packager Check"
ID="com.example.packager-check"
LOG="$OUT/log.txt"
mkdir -p "$OUT"
say() { printf '\n== %s\n' "$*" | tee -a "$LOG"; }
run() { echo "\$ $*" >> "$LOG"; "$@" 2>&1 | tee -a "$LOG"; }

build() {
  say "build"
  rm -rf "$OUT/src" "$OUT/dist"
  mkdir -p "$OUT/src/assets"
  (cd "$REPO" && cargo build -q --release -p packager-cli)
  printf 'int main(void){return 0;}\n' > "$OUT/src/main.c"
  cc -arch arm64 -arch x86_64 -O2 -o "$OUT/src/packager-check" "$OUT/src/main.c"
  # Icon and window background from a system icon, so nothing has to be downloaded.
  local sys_icns=/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericApplicationIcon.icns
  sips -s format png "$sys_icns" --out "$OUT/src/assets/icon.png" >/dev/null
  # A 72-DPI background fills a 540×380 window; a 144-DPI copy named @2x tests Retina sizing.
  sips -z 380 540 -s dpiWidth 72 -s dpiHeight 72 "$OUT/src/assets/icon.png" --out "$OUT/src/assets/background.png" >/dev/null
  cat > "$OUT/src/packager.toml" <<EOF
[app]
name = "$NAME"
identifier = "$ID"
version = "1.0.0"
icon = "assets/icon.png"
[app.binaries]
macos-universal = "packager-check"
[package.app]
[package.dmg]
background = "assets/background.png"
icon_size = 128
app_position = [140, 180]
applications_position = [400, 180]
[package.pkg]
[sign.apple]
identity = "-"
hardened_runtime = true
[build]
out_dir = "$OUT/dist"
EOF
  run "$REPO/target/release/packager" build --config "$OUT/src/packager.toml"
  run "$REPO/target/release/packager" verify "$OUT/dist/$NAME.app"
  run "$REPO/target/release/packager" verify "$OUT/dist/$NAME-1.0.0.dmg"
  run "$REPO/target/release/packager" verify "$OUT/dist/$NAME-1.0.0.pkg"
  run codesign --verify --deep --strict --verbose=2 "$OUT/dist/$NAME.app"
  run hdiutil verify "$OUT/dist/$NAME-1.0.0.dmg"
}

finder() {
  say "finder"
  local dmg="$OUT/dist/$NAME-1.0.0.dmg"
  [ -f "$dmg" ] || build
  hdiutil detach "/Volumes/$NAME" -quiet 2>/dev/null || true
  # Attach with browsing on, then have Finder open the window the way a user would.
  run hdiutil attach "$dmg"
  sleep 2
  open "/Volumes/$NAME"
  sleep 3
  # Finder's own view of the window (macOS may ask once to let Terminal control Finder).
  osascript > "$OUT/finder-report.txt" 2>&1 <<EOF || true
tell application "Finder"
  set d to disk "$NAME"
  set w to container window of d
  set r to ""
  try
    set b to bounds of w
    set r to r & "bounds: " & (item 1 of b) & ", " & (item 2 of b) & ", " & (item 3 of b) & ", " & (item 4 of b) & linefeed
  on error e
    set r to r & "bounds: ERROR " & e & linefeed
  end try
  try
    set r to r & "view: " & (current view of w as text) & linefeed
    set r to r & "toolbar visible: " & (toolbar visible of w as text) & linefeed
  on error e
    set r to r & "window: ERROR " & e & linefeed
  end try
  try
    set opts to icon view options of w
    set r to r & "icon size: " & (icon size of opts as text) & linefeed
    set r to r & "arrangement: " & (arrangement of opts as text) & linefeed
    try
      set bp to background picture of opts
      set r to r & "background picture: " & (bp as text) & linefeed
    on error e
      set r to r & "background picture: NONE (" & e & ")" & linefeed
    end try
  on error e
    set r to r & "icon view options: ERROR " & e & linefeed
  end try
  try
    set names to name of every item of d
    repeat with n in names
      set p to position of item (n as text) of d
      set r to r & "item: " & (n as text) & " at " & (item 1 of p) & ", " & (item 2 of p) & linefeed
    end repeat
  on error e
    set r to r & "items: ERROR " & e & linefeed
  end try
  return r
end tell
EOF
  tee -a "$LOG" < "$OUT/finder-report.txt"
  # Screenshot: the window region if Finder gave bounds, else the whole screen. Needs Screen
  # Recording permission for Terminal (System Settings > Privacy & Security > Screen Recording).
  local b shot=failed
  b=$(sed -n 's/^bounds: \([0-9-]*\), \([0-9-]*\), \([0-9-]*\), \([0-9-]*\)$/\1 \2 \3 \4/p' "$OUT/finder-report.txt")
  if [ -n "$b" ]; then
    read -r x1 y1 x2 y2 <<< "$b"
    screencapture -x -R "$x1,$((y1 > 28 ? y1 - 28 : 0)),$((x2 - x1)),$((y2 - y1 + 28))" "$OUT/dmg-window.png" 2>>"$LOG" && shot=window
  fi
  if [ "$shot" = failed ]; then
    screencapture -x "$OUT/dmg-window.png" 2>>"$LOG" && shot=screen
  fi
  if [ "$shot" = failed ]; then
    echo "screenshot FAILED: give Terminal Screen Recording permission, then rerun: $0 finder" | tee -a "$LOG"
  else
    echo "screenshot ($shot): $OUT/dmg-window.png" | tee -a "$LOG"
  fi
  hdiutil detach "/Volumes/$NAME" -quiet || true
}

install() {
  say "install (sudo)"
  local pkg="$OUT/dist/$NAME-1.0.0.pkg"
  [ -f "$pkg" ] || build
  run sudo installer -pkg "$pkg" -target / -verboseR
  run pkgutil --pkg-info "$ID"
  run pkgutil --files "$ID"
  run ls -la "/Applications/$NAME.app/Contents/MacOS"
  run stat -f '%Su:%Sg %Sp %N' "/Applications/$NAME.app" "/Applications/$NAME.app/Contents/MacOS/packager-check"
  run codesign --verify --deep --strict --verbose=2 "/Applications/$NAME.app"
  run "/Applications/$NAME.app/Contents/MacOS/packager-check" && echo "app ran: exit 0" | tee -a "$LOG"
  # Upgrade path: reinstalling must replace the app in place, not relocate it.
  run sudo installer -pkg "$pkg" -target /
  run ls -d "/Applications/$NAME.app"
}

cleanup() {
  say "cleanup (sudo)"
  hdiutil detach "/Volumes/$NAME" -quiet 2>/dev/null || true
  run sudo rm -rf "/Applications/$NAME.app"
  run sudo pkgutil --forget "$ID" || true
}

case "${1:-all}" in
  build) build ;;
  finder) finder ;;
  install) install ;;
  cleanup) cleanup ;;
  all) : > "$LOG"; build; finder; install; cleanup ;;
  *) echo "usage: $0 [build|finder|install|cleanup|all]"; exit 2 ;;
esac
say "done — log: $LOG"

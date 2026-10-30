#!/usr/bin/env bash
# Store screenshots for every listing language, from an Android 13+ EMULATOR only: the
# debug build's Demo hook (app/src/debug) wipes the AgePony vault and seeds demo keys.
# Writes fastlane/metadata/android/<locale>/images/phoneScreenshots/*.png for Play and F-Droid.
set -euo pipefail
cd "$(dirname "$0")/.."

PKG=com.agepony.app
ACT=com.agepony.app.MainActivity
OUT=fastlane/metadata/android

[ "$(adb devices | grep -c 'device$')" = 1 ] || { echo "Connect exactly one emulator"; exit 1; }
qemu="$(adb shell getprop ro.kernel.qemu | tr -d '\r')$(adb shell getprop ro.boot.qemu | tr -d '\r')"
case "$qemu" in *1*) ;; *) echo "Not an emulator. The demo wipes the AgePony vault, so it only runs on an emulator."; exit 1 ;; esac
sdk="$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
[ "$sdk" -ge 33 ] || { echo "Needs Android 13 (API 33) or later for per-app languages, found API $sdk"; exit 1; }

./gradlew -q :app:installFossDebug

demo() { adb shell am broadcast -a com.android.systemui.demo -e command "$@" >/dev/null; }

cleanup() {
  demo exit || true
  adb shell cmd locale set-app-locales "$PKG" --locales "" >/dev/null 2>&1 || true
  adb shell wm size reset || true
  adb shell wm density reset || true
  adb shell svc power stayon false || true
}
trap cleanup EXIT

adb shell wm size 1080x1920
adb shell wm density 420
adb shell svc power stayon usb
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard
sleep 2

adb shell settings put global sysui_demo_allowed 1
demo enter
demo clock -e hhmm 0941
demo battery -e level 100 -e plugged false
demo network -e wifi show -e level 4 -e mobile show -e level 4 -e datatype none
demo notifications -e visible false

capture() {
  local file="$1"
  adb exec-out screencap -p > "$file"
  if [ "$(wc -c < "$file")" -lt 40000 ]; then
    echo "$file is blank. Keep the emulator screen on and run again."
    exit 1
  fi
}

for pair in en-US:en:en-US de-DE:de:de-DE es-ES:es:es-ES fr-FR:fr:fr-FR pt-BR:pt-BR:pt-BR ru-RU:ru:ru-RU zh-CN:zh-Hans:zh-Hans-CN; do
  IFS=: read -r dir lang locale <<< "$pair"
  shots="$OUT/$dir/images/phoneScreenshots"
  mkdir -p "$shots"
  rm -f "$shots"/*.png
  adb shell am force-stop "$PKG"
  adb shell cmd locale set-app-locales "$PKG" --locales "$locale"
  adb shell am start -W -n "$PKG/$ACT" --ez demo_seed true --es demo_lang "$lang" --es demo_screen files >/dev/null
  sleep 8
  i=1
  for screen in files identities text notes settings; do
    if [ "$i" -gt 1 ]; then
      adb shell am force-stop "$PKG"
      adb shell am start -W -n "$PKG/$ACT" --es demo_screen "$screen" >/dev/null
      sleep 4
    fi
    capture "$shots/${i}_${screen}.png"
    i=$((i + 1))
  done
  echo "$dir done"
done

file "$OUT"/en-US/images/phoneScreenshots/*.png

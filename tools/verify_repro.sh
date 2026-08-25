#!/usr/bin/env bash
# verify_repro.sh: reproducible build gate for AgePony releases.
#
# Rebuilds a tag from clean clones and compares APK contents byte for byte,
# ignoring only the signature (META-INF/*.SF, *.RSA, *.DSA, *.EC and
# MANIFEST.MF plus the APK signing block, which lives outside the ZIP
# entries and is never extracted).
#
# Usage:
#   tools/verify_repro.sh rebuild <tag> [candidate.apk]
#       Clone <tag> twice into isolated build roots, build
#       :app:assembleFossRelease in each, prove the two builds have
#       identical content, then (if given) compare candidate.apk against
#       the fresh build. Exit 0 only if everything matches.
#
#   tools/verify_repro.sh compare <a.apk> <b.apk>
#       Content-compare two APKs, ignoring signatures. Exit 0 on identical.
#
#   tools/verify_repro.sh content-hash <apk>
#       Print a stable SHA-256 over the APK contents with signatures
#       stripped. Two APKs with the same content hash will pass F-Droid's
#       signature-copy verification against each other.
#
# Environment (all optional, defaults suit a standard foss-flavor app):
#   REPO_URL      clone source. Default: the origin remote of the current
#                 directory's git repo, so running from a checkout of the
#                 app just works.
#   GRADLE_TASK   build task. Default: :app:assembleFossRelease
#   APK_REL_PATH  built APK path relative to the clone root. Default:
#                 app/build/outputs/apk/foss/release/app-foss-release.apk
#   WORK          fixed work directory (default: mktemp under /tmp)
#
# The work directory is always kept, so the clean build (buildA.apk) is
# available for signing after a PASS. Delete it manually when done.
#
# Never compare a working-tree build to anything. Clean clones only.
# See docs/REPRODUCIBLE_BUILDS.md for the release procedure this gates.

set -euo pipefail

REPO_URL="${REPO_URL:-$(git remote get-url origin 2>/dev/null || true)}"
GRADLE_TASK="${GRADLE_TASK:-:app:assembleFossRelease}"
APK_REL_PATH="${APK_REL_PATH:-app/build/outputs/apk/foss/release/app-foss-release.apk}"

say()  { printf '%s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

sha_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Per-entry SHA-256 manifest of an APK, read directly from the ZIP.
# Never extracts to the filesystem: APKs contain resource names that
# differ only by letter case (AGP's shortened res/ names), and a
# case-insensitive filesystem (macOS) silently collapses those on
# extraction, which corrupts any comparison or hash done on disk.
apk_manifest() {
    python3 - "$1" <<'PYEOF'
import hashlib, sys, zipfile
SIG_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC", "MANIFEST.MF")
with zipfile.ZipFile(sys.argv[1]) as z:
    names = sorted(n for n in z.namelist() if not n.endswith("/"))
    for n in names:
        if n.startswith("META-INF/") and n.endswith(SIG_SUFFIXES):
            continue
        h = hashlib.sha256(z.read(n)).hexdigest()
        print("%s  %s" % (h, n))
PYEOF
}

# Stable digest over APK contents: SHA-256 of the sorted per-entry
# manifest, signature files ignored. Filesystem-independent.
content_hash() {
    local t h
    t="$(mktemp)"
    apk_manifest "$1" > "$t"
    h="$(sha_file "$t")"
    rm -f "$t"
    printf '%s\n' "$h"
}

dex_report() {
    local apk="$1"
    python3 - "$apk" <<'PYEOF'
import hashlib, re, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    for n in sorted(z.namelist()):
        if re.fullmatch(r"classes\d*\.dex", n):
            data = z.read(n)
            print("    %s  sha256=%s  size=%d"
                  % (n, hashlib.sha256(data).hexdigest(), len(data)))
            m = re.search(rb"~~R8\{[^}]*\}", data)
            if m:
                print("      %s" % m.group(0).decode())
PYEOF
}

cmd_compare() {
    local a="$1" b="$2" t rc=0
    [ -f "$a" ] || fail "no such file: $a"
    [ -f "$b" ] || fail "no such file: $b"
    t="$(mktemp -d)"
    apk_manifest "$a" > "$t/a.manifest"
    apk_manifest "$b" > "$t/b.manifest"
    if diff "$t/a.manifest" "$t/b.manifest" > "$t/diff.txt" 2>&1; then
        say "IDENTICAL content: $a == $b (signatures ignored)"
        say "  content hash: $(sha_file "$t/a.manifest")"
    else
        rc=1
        say "CONTENT DIFFERS between $a and $b:"
        sed 's/^/  /' "$t/diff.txt"
        say "  $a:"
        dex_report "$a"
        say "  $b:"
        dex_report "$b"
    fi
    rm -rf "$t"
    return "$rc"
}

find_android_home() {
    if [ -n "${ANDROID_HOME:-}" ]; then return 0; fi
    if [ -n "${ANDROID_SDK_ROOT:-}" ]; then ANDROID_HOME="$ANDROID_SDK_ROOT"; return 0; fi
    local cand
    for cand in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk" /usr/lib/android-sdk; do
        if [ -d "$cand" ]; then ANDROID_HOME="$cand"; return 0; fi
    done
    fail "Android SDK not found. Set ANDROID_HOME and rerun."
}

build_leg() {
    local tag="$1" leg="$2" work="$3"
    say "[$leg] clean clone of $tag from $REPO_URL"
    git clone --quiet --branch "$tag" --depth 1 "$REPO_URL" "$work/src$leg"
    ( cd "$work/src$leg" && \
      env GRADLE_USER_HOME="$work/gradle$leg" ANDROID_HOME="$ANDROID_HOME" \
          ./gradlew --no-daemon "$GRADLE_TASK" )
    cp "$work/src$leg/$APK_REL_PATH" "$work/build$leg.apk"
    say "[$leg] built $work/build$leg.apk"
}

cmd_rebuild() {
    local tag="$1" candidate="${2:-}" work hA hB
    [ -n "$REPO_URL" ] || fail "REPO_URL is not set and no git origin remote found here"
    if [ -n "${WORK:-}" ]; then
        work="$WORK"
        mkdir -p "$work"
    else
        work="$(mktemp -d /tmp/agepony-repro.XXXXXX)"
    fi
    say "work directory: $work"

    find_android_home
    say "using Android SDK: $ANDROID_HOME"

    build_leg "$tag" A "$work"
    build_leg "$tag" B "$work"

    hA="$(content_hash "$work/buildA.apk")"
    hB="$(content_hash "$work/buildB.apk")"
    say "content hash A: $hA"
    say "content hash B: $hB"
    if [ "$hA" != "$hB" ]; then
        say "The same tag built twice from clean clones does not match itself."
        say "The build is nondeterministic on this machine. Details:"
        cmd_compare "$work/buildA.apk" "$work/buildB.apk" || true
        fail "nondeterministic build for $tag (work dir kept: $work)"
    fi
    say "PASS: two clean-clone builds of $tag are content-identical."
    say "canonical content hash for $tag: $hA"
    dex_report "$work/buildA.apk"

    if [ -n "$candidate" ]; then
        say "comparing candidate against fresh clean build..."
        if ! cmd_compare "$candidate" "$work/buildA.apk"; then
            fail "candidate $candidate does NOT match a clean build of $tag (work dir kept: $work)"
        fi
        say "PASS: $candidate matches a clean build of $tag."
    fi

    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        {
            echo "### Reproducible check: $tag"
            echo ""
            echo "- content hash: \`$hA\`"
            echo "- two independent clean-clone builds: identical"
            [ -n "$candidate" ] && echo "- candidate APK: matches"
        } >> "$GITHUB_STEP_SUMMARY"
    fi

    say "kept work directory: $work"
    say "the clean tag build is $work/buildA.apk; sign that file for release."
    say "delete the directory when you are done with it."
}

case "${1:-}" in
    rebuild)
        [ $# -ge 2 ] || fail "usage: $0 rebuild <tag> [candidate.apk]"
        cmd_rebuild "$2" "${3:-}"
        ;;
    compare)
        [ $# -eq 3 ] || fail "usage: $0 compare <a.apk> <b.apk>"
        cmd_compare "$2" "$3"
        ;;
    content-hash)
        [ $# -eq 2 ] || fail "usage: $0 content-hash <apk>"
        content_hash "$2"
        ;;
    *)
        sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac

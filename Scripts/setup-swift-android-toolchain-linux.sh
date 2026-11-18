#!/usr/bin/env bash
# Installs the Swift 6.4.0 Android cross-compile toolchain (Linux host
# toolchain + Android NDK + Swift SDK for Android) used by
# .github/workflows/ci-android.yml. Idempotent: safe to re-run against a warm
# cache.
#
# The workflow's env governs versions and paths. Download checksums are pinned
# here, so bumping SWIFT_VERSION or NDK_VERSION needs new checksums below.

set -euo pipefail

SWIFT_VERSION="${SWIFT_VERSION:-6.4.0}"
SWIFT_SDK_NAME="${SWIFT_SDK_NAME:-swift-${SWIFT_VERSION}-RELEASE_android}"
SWIFT_SDK_CHECKSUM="${SWIFT_SDK_CHECKSUM:-21fb555122a3d801ad943d48df7ebffdd8824de61c25c180bb792d3edaee0b43}"
NDK_VERSION="${NDK_VERSION:-30.0.16248370}"
SWIFT_HOST="${SWIFT_HOST:-${GITHUB_WORKSPACE:-$HOME}/.ci-swift-host}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${GITHUB_WORKSPACE:-$HOME}/.ci-android-sdk}"
ANDROID_HOME="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_SDK_ROOT/ndk/$NDK_VERSION}"
ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-$ANDROID_NDK_HOME}"

SWIFT_HOST_URL="https://download.swift.org/swift-${SWIFT_VERSION}-release/ubuntu2404/swift-${SWIFT_VERSION}-RELEASE/swift-${SWIFT_VERSION}-RELEASE-ubuntu24.04.tar.gz"
SWIFT_SDK_URL="https://download.swift.org/swift-${SWIFT_VERSION}-release/android-sdk/swift-${SWIFT_VERSION}-RELEASE/${SWIFT_SDK_NAME}.artifactbundle.tar.gz"
NDK_ZIP_URL="https://dl.google.com/android/repository/android-ndk-r30-linux.zip"

SWIFT_HOST_SHA256="69f7b2b4dbce6090b6c92194b71149a057e16269093b5a9dded38afc4a05094e"
SWIFT_SIGNING_KEY_FPR="52BB7E3DE28A71BE22EC05FFEF80A866B47A981F"
SWIFT_SIGNING_KEY_URL="https://swift.org/keys/release-key-swift-6.x.asc"
NDK_SHA1="5107f898313790e449e87eee2183d9a20602dee9"
NDK_SHA256="753611f410d002cfcd3f3dc2ef49aad532089d3180b436c060a90bf0fcb64df2"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

fail() {
    echo "::error::$*" >&2
    exit 1
}

# verify_sha <sha1|sha256> <file> <expected-hex>
verify_sha() {
    local algo="$1" file="$2" expected="$3" actual
    actual="$("${algo}sum" "$file" | cut -d' ' -f1)"
    [[ "$actual" == "$expected" ]] ||
        fail "$(basename "$file"): $algo mismatch (expected $expected, got $actual)"
}

export ANDROID_SDK_ROOT ANDROID_HOME ANDROID_NDK_HOME ANDROID_NDK_ROOT

# ---------------------------------------------------------------------------
# 1. Linux host toolchain. Xcode's Swift can't drive the Android Swift SDK:
#    cross-compiling needs an open-source host toolchain whose version
#    matches the SDK exactly. Verified by signature and checksum before
#    extraction.
# ---------------------------------------------------------------------------
say "Swift ${SWIFT_VERSION} Linux host toolchain"
if [[ -x "$SWIFT_HOST/usr/bin/swift" ]]; then
    echo "Swift ${SWIFT_VERSION} host toolchain already installed at $SWIFT_HOST"
else
    tarball="$work/swift-host.tar.gz"
    curl -fsSL -o "$tarball" "$SWIFT_HOST_URL"
    curl -fsSL -o "$tarball.sig" "$SWIFT_HOST_URL.sig"
    curl -fsSL -o "$work/swift-key.asc" "$SWIFT_SIGNING_KEY_URL"
    export GNUPGHOME="$work/gnupg"
    mkdir -m 700 "$GNUPGHOME"
    gpg --batch --quiet --import "$work/swift-key.asc" ||
        fail "swift signing key: import failed"
    gpg_rc=0
    gpg_status="$(gpg --batch --status-fd 1 --verify "$tarball.sig" "$tarball" 2>/dev/null)" || gpg_rc=$?
    # Require a good signature made by the pinned key itself.
    if [[ "$gpg_rc" -ne 0 ]] ||
        ! grep -q '^\[GNUPG:\] GOODSIG ' <<<"$gpg_status" ||
        grep -qE '^\[GNUPG:\] (EXPKEYSIG|REVKEYSIG|EXPSIG|BADSIG|ERRSIG) ' <<<"$gpg_status" ||
        ! grep -q "^\[GNUPG:\] VALIDSIG .* $SWIFT_SIGNING_KEY_FPR\$" <<<"$gpg_status"; then
        echo "$gpg_status" >&2
        fail "swift-host.tar.gz: signature check failed against key $SWIFT_SIGNING_KEY_FPR"
    fi
    verify_sha sha256 "$tarball" "$SWIFT_HOST_SHA256"
    mkdir -p "$SWIFT_HOST"
    # The tarball nests everything under a
    # swift-${SWIFT_VERSION}-RELEASE-ubuntu24.04/ directory; strip it so
    # $SWIFT_HOST is the toolchain root.
    tar -xzf "$tarball" -C "$SWIFT_HOST" --strip-components=1
    rm -f "$tarball"
fi
export PATH="$SWIFT_HOST/usr/bin:$PATH"
if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "$SWIFT_HOST/usr/bin" >> "$GITHUB_PATH"
    # A build-tool plugin subprocess can run with a restricted PATH that
    # doesn't see $SWIFT_HOST; a bare `swift` on the standard PATH covers it.
    for exe in "$SWIFT_HOST"/usr/bin/swift*; do
        sudo ln -sf "$exe" "/usr/bin/$(basename "$exe")"
    done
fi

# ---------------------------------------------------------------------------
# 2. Android NDK.
# ---------------------------------------------------------------------------
say "Android NDK ${NDK_VERSION}"
if [[ -f "$ANDROID_NDK_HOME/source.properties" ]]; then
    echo "NDK restored from cache: $ANDROID_NDK_HOME"
else
    curl -fsSL -o "$work/ndk.zip" "$NDK_ZIP_URL"
    verify_sha sha1 "$work/ndk.zip" "$NDK_SHA1"
    verify_sha sha256 "$work/ndk.zip" "$NDK_SHA256"
    mkdir -p "$work/ndk-staging" "$(dirname "$ANDROID_NDK_HOME")"
    unzip -q "$work/ndk.zip" -d "$work/ndk-staging"
    mv "$work"/ndk-staging/*/ "$ANDROID_NDK_HOME"
fi
if [[ -n "${GITHUB_PATH:-}" ]]; then
    # Android build support falls back to the standard
    # google-android-ndk-*-installer package location when no NDK env
    # override is visible to it; these symlinks satisfy that fallback too.
    sudo mkdir -p /usr/lib/android-sdk/ndk
    sudo ln -sfn "$ANDROID_NDK_HOME" "/usr/lib/android-sdk/ndk/$NDK_VERSION"
    sudo ln -sfn "$ANDROID_NDK_HOME" /usr/lib/android-ndk
fi

# ---------------------------------------------------------------------------
# 3. Swift SDK for Android.
#
# GOTCHA: the artifactbundle ships with no NDK sysroot until its own setup
# script runs — skip it and every C target fails with a misleading
# "'string.h' file not found", which reads like an unrelated dependency
# problem and is not one.
#
# GOTCHA: that script reads ANDROID_NDK_HOME, not the more commonly exported
# ANDROID_NDK_ROOT.
# ---------------------------------------------------------------------------
say "Swift SDK for Android ${SWIFT_VERSION}"
if ! swift sdk list 2>/dev/null | grep -q "$SWIFT_SDK_NAME"; then
    swift sdk install "$SWIFT_SDK_URL" --checksum "$SWIFT_SDK_CHECKSUM"
fi
bundle="$(find "$HOME" -maxdepth 6 -type d -name "${SWIFT_SDK_NAME}.artifactbundle" 2>/dev/null | head -1)"
if [[ -z "$bundle" ]]; then
    fail "${SWIFT_SDK_NAME}.artifactbundle not found under \$HOME after swift sdk install"
fi
ANDROID_NDK_HOME="$ANDROID_NDK_HOME" bash "$bundle/swift-android/scripts/setup-android-sdk.sh"

say "Installed versions"
cat <<EOF
  swift (host)       $("$SWIFT_HOST/usr/bin/swift" --version 2>&1 | head -1)
  Swift SDK          ${SWIFT_SDK_NAME}  (sha256 ${SWIFT_SDK_CHECKSUM})
  NDK                ${NDK_VERSION}
  ANDROID_SDK_ROOT   ${ANDROID_SDK_ROOT}
  ANDROID_NDK_HOME   ${ANDROID_NDK_HOME}
EOF

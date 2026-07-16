#!/bin/bash
#
# build.sh - Build UE4 Dumper for Android (ARM64)
#
# Requirements:
#   1. Android NDK (r21 or newer recommended)
#   2. Set ANDROID_NDK_HOME environment variable, or edit NDK_PATH below
#
# Usage:
#   ./build.sh                    # Build for ARM64
#   ./build.sh x86_64             # Build for x86_64 (Android emulator)
#   ./build.sh all                # Build for both architectures
#
# Output:
#   build/arm64-v8a/ue4_dumper    (ARM64 binary)
#   build/x86_64/ue4_dumper       (x86_64 binary)
#

set -e

# ─── Configuration ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

# Try to find NDK
if [ -n "$ANDROID_NDK_HOME" ]; then
    NDK_PATH="$ANDROID_NDK_HOME"
elif [ -n "$ANDROID_NDK" ]; then
    NDK_PATH="$ANDROID_NDK"
elif [ -d "$HOME/Android/Sdk/ndk" ]; then
    NDK_PATH=$(ls -d "$HOME/Android/Sdk/ndk/"*/ 2>/dev/null | sort -V | tail -1)
elif [ -d "$HOME/ndk" ]; then
    NDK_PATH="$HOME/ndk"
else
    echo "============================================="
    echo "  Android NDK not found!"
    echo "============================================="
    echo ""
    echo "  Please set ANDROID_NDK_HOME environment variable:"
    echo "    export ANDROID_NDK_HOME=/path/to/ndk"
    echo ""
    echo "  Download NDK from:"
    echo "    https://developer.android.com/ndk/downloads"
    echo ""
    echo "  -- OR -- Building for local (Linux) target instead"
    echo ""
    BUILD_LOCAL=1
fi

# Minimum API level: 21 (Android 5.0)
API_LEVEL=${API_LEVEL:-21}

# ─── Colors ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[!]${NC} $1"; }

# ─── Build function ─────────────────────────────────────────────────────
build_target() {
    local ABI="$1"
    local TARGET_NAME="$2"
    local TOOLCHAIN_PREFIX="$3"

    echo ""
    echo "============================================="
    echo "  Building for ${ABI} (${TARGET_NAME})"
    echo "============================================="

    local OUT_DIR="${BUILD_DIR}/${ABI}"

    if [ -n "$BUILD_LOCAL" ]; then
        # Local Linux build (uses system compiler)
        info "Using system compiler (local build)"
        mkdir -p "$OUT_DIR"
        cd "$OUT_DIR"
        cmake "$SCRIPT_DIR" \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_SYSTEM_PROCESSOR="${TARGET_NAME}"
        cmake --build . -j$(nproc)
        ok "Built: ${OUT_DIR}/ue4_dumper"
        file "${OUT_DIR}/ue4_dumper"
        return
    fi

    # Android NDK cross-compile
    local TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/linux-x86_64"
    if [ ! -d "$TOOLCHAIN" ]; then
        # Try Windows host toolchain
        TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/windows-x86_64"
    fi
    if [ ! -d "$TOOLCHAIN" ]; then
        # Try macOS host toolchain
        TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/darwin-x86_64"
    fi

    if [ ! -d "$TOOLCHAIN" ]; then
        err "Cannot find NDK toolchain at ${TOOLCHAIN}"
        err "Please check your NDK installation"
        exit 1
    fi

    local CC="${TOOLCHAIN}/bin/${TOOLCHAIN_PREFIX}${API_LEVEL}-clang"
    local CXX="${TOOLCHAIN}/bin/${TOOLCHAIN_PREFIX}${API_LEVEL}-clang++"

    if [ ! -f "$CXX" ]; then
        # Try without API level suffix (older NDK)
        CC="${TOOLCHAIN}/bin/${TOOLCHAIN_PREFIX}-clang"
        CXX="${TOOLCHAIN}/bin/${TOOLCHAIN_PREFIX}-clang++"
    fi

    if [ ! -f "$CXX" ]; then
        err "Compiler not found: ${CXX}"
        exit 1
    fi

    local SYSROOT="${TOOLCHAIN}/sysroot"
    info "CC:      ${CC}"
    info "CXX:     ${CXX}"
    info "SYSROOT: ${SYSROOT}"
    info "API:     ${API_LEVEL}"

    mkdir -p "$OUT_DIR"
    cd "$OUT_DIR"

    cmake "$SCRIPT_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_SYSTEM_NAME=Android \
        -DCMAKE_SYSTEM_VERSION="${API_LEVEL}" \
        -DCMAKE_ANDROID_ARCH_ABI="${ABI}" \
        -DCMAKE_ANDROID_NDK="${NDK_PATH}" \
        -DCMAKE_ANDROID_STL_TYPE=c++_static \
        -DCMAKE_C_COMPILER="${CC}" \
        -DCMAKE_CXX_COMPILER="${CXX}" \
        -DCMAKE_SYSROOT="${SYSROOT}" \
        -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
        -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
        -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
        -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY

    cmake --build . -j$(nproc)

    # Strip
    local STRIP="${TOOLCHAIN}/bin/llvm-strip"
    if [ -f "$STRIP" ]; then
        "$STRIP" "${OUT_DIR}/ue4_dumper"
    fi

    ok "Built: ${OUT_DIR}/ue4_dumper"
    ls -lh "${OUT_DIR}/ue4_dumper"
}

# ─── Package function ───────────────────────────────────────────────────
package() {
    info "Creating deploy packages..."
    local DIST_DIR="${BUILD_DIR}/dist"
    mkdir -p "$DIST_DIR"

    for ABI in arm64-v8a x86_64; do
        local SRC="${BUILD_DIR}/${ABI}/ue4_dumper"
        if [ -f "$SRC" ]; then
            cp "$SRC" "${DIST_DIR}/ue4_dumper_${ABI}"
            ok "Packaged: ${DIST_DIR}/ue4_dumper_${ABI}"
        fi
    done

    # Create a makeself-style deploy script
    cat > "${DIST_DIR}/deploy.sh" << 'DEPLOY_SCRIPT'
#!/system/bin/sh
# UE4 Dumper deployment script
# Push to device: adb push ue4_dumper_arm64-v8a /data/local/tmp/ue4_dumper
# Run: su -c 'chmod +x /data/local/tmp/ue4_dumper && /data/local/tmp/ue4_dumper <PID>'

ARCH=$(uname -m)
BASE=/data/local/tmp

case "$ARCH" in
    aarch64|arm64*)
        BINARY="ue4_dumper_arm64-v8a"
        ;;
    x86_64|amd64)
        BINARY="ue4_dumper_x86_64"
        ;;
    *)
        echo "Unknown architecture: $ARCH"
        exit 1
        ;;
esac

echo "Deploying UE4 Dumper for ${ARCH}..."
cp "${BINARY}" "${BASE}/ue4_dumper"
chmod 755 "${BASE}/ue4_dumper"
echo "Installed to ${BASE}/ue4_dumper"
echo ""
echo "Usage: su -c '${BASE}/ue4_dumper <PID> [--ue4-version <ver>]'"
DEPLOY_SCRIPT

    ok "Deploy script created: ${DIST_DIR}/deploy.sh"
}

# ─── Main ───────────────────────────────────────────────────────────────
ARCH="${1:-arm64}"

case "$ARCH" in
    arm64|arm64-v8a)
        build_target "arm64-v8a" "aarch64" "aarch64-linux-android"
        ;;
    x86_64|x64)
        build_target "x86_64" "x86_64" "x86_64-linux-android"
        ;;
    all)
        build_target "arm64-v8a" "aarch64" "aarch64-linux-android"
        build_target "x86_64" "x86_64" "x86_64-linux-android"
        package
        ;;
    local)
        BUILD_LOCAL=1
        UARCH=$(uname -m)
        if [ "$UARCH" = "x86_64" ]; then
            build_target "x86_64" "x86_64" ""
        elif [ "$UARCH" = "aarch64" ]; then
            build_target "arm64-v8a" "aarch64" ""
        else
            err "Unknown local architecture: $UARCH"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [arm64|x86_64|all|local]"
        exit 1
        ;;
esac

echo ""
ok "Build complete!"
echo ""
echo "To deploy to a phone:"
echo "  adb push build/arm64-v8a/ue4_dumper /data/local/tmp/"
echo "  adb shell"
echo "  su -c 'chmod +x /data/local/tmp/ue4_dumper'"
echo "  su -c '/data/local/tmp/ue4_dumper --list'"
echo "  su -c '/data/local/tmp/ue4_dumper <PID> --ue4-version 426'"
echo ""

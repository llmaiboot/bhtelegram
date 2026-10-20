#!/usr/bin/env bash
# Builds libtdjson.so (TDLib JSON interface) for Android: arm64-v8a (phones) and x86_64 (emulator).
# Usage: scripts/build-tdlib-android.sh [TD_SOURCE_DIR] [OUT_DIR]
# Requires: Android NDK under $ANDROID_HOME/ndk/$NDK_VERSION, cmake, ninja, gperf, perl, make.
set -euo pipefail

TD_DIR=$(realpath "${1:-$HOME/projects/td}")
OUT_DIR=$(realpath -m "${2:-$HOME/projects/bhtelegram-deps/android}")
ANDROID_HOME=${ANDROID_HOME:-/opt/android-sdk}
NDK_VERSION=${NDK_VERSION:-29.0.14206865}
NDK=$ANDROID_HOME/ndk/$NDK_VERSION
OPENSSL_VERSION=${OPENSSL_VERSION:-openssl-3.3.2}
API=24
ABIS=${ABIS:-"arm64-v8a x86_64"}
JOBS=${JOBS:-$(nproc)}
WORK=${WORK:-/tmp/bh-tdlib-android}
TOOLBIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin

[ -d "$NDK" ] || { echo "NDK not found: $NDK"; exit 1; }
mkdir -p "$WORK" "$OUT_DIR"

# 1. OpenSSL (static)
if [ ! -d "$WORK/$OPENSSL_VERSION" ]; then
  echo "== Downloading OpenSSL $OPENSSL_VERSION"
  curl -sfL "https://github.com/openssl/openssl/releases/download/$OPENSSL_VERSION/$OPENSSL_VERSION.tar.gz" | tar xz -C "$WORK"
fi
for ABI in $ABIS; do
  [ -f "$WORK/openssl/$ABI/lib/libssl.a" ] && continue
  echo "== OpenSSL for $ABI"
  case $ABI in
    arm64-v8a) T=android-arm64 ;;
    x86_64) T=android-x86_64 ;;
    *) echo "unsupported $ABI"; exit 1 ;;
  esac
  (
    cd "$WORK/$OPENSSL_VERSION"
    export ANDROID_NDK_ROOT=$NDK PATH=$TOOLBIN:$PATH
    make distclean >/dev/null 2>&1 || true
    LDFLAGS=-Wl,-z,max-page-size=16384 ./Configure $T no-shared no-tests no-docs -D__ANDROID_API__=$API >/dev/null
    make -j"$JOBS" -s build_libs >/dev/null
    mkdir -p "$WORK/openssl/$ABI/lib"
    cp libcrypto.a libssl.a "$WORK/openssl/$ABI/lib/"
    cp -r include "$WORK/openssl/$ABI/"
  )
done

# 2. TDLib source generation (host)
if [ ! -f "$WORK/native-gen.done" ]; then
  echo "== Generating TDLib sources"
  mkdir -p "$WORK/native"
  (cd "$WORK/native" && cmake -GNinja -DTD_GENERATE_SOURCE_FILES=ON "$TD_DIR" >/dev/null && cmake --build . >/dev/null)
  touch "$WORK/native-gen.done"
fi

# 3. tdjson per ABI
for ABI in $ABIS; do
  echo "== TDLib tdjson for $ABI"
  mkdir -p "$WORK/build-$ABI" "$OUT_DIR/$ABI"
  (
    cd "$WORK/build-$ABI"
    cmake -GNinja "$TD_DIR" \
      -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
      -DANDROID_ABI=$ABI -DANDROID_PLATFORM=android-$API -DANDROID_STL=c++_static \
      -DCMAKE_BUILD_TYPE=MinSizeRel \
      -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-z,max-page-size=16384" \
      -DOPENSSL_ROOT_DIR="$WORK/openssl/$ABI" \
      -DOPENSSL_USE_STATIC_LIBS=TRUE \
      -DOPENSSL_INCLUDE_DIR="$WORK/openssl/$ABI/include" \
      -DOPENSSL_CRYPTO_LIBRARY="$WORK/openssl/$ABI/lib/libcrypto.a" \
      -DOPENSSL_SSL_LIBRARY="$WORK/openssl/$ABI/lib/libssl.a" \
      -DTD_ENABLE_LTO=OFF >/dev/null
    cmake --build . --target tdjson -j"$JOBS"
  )
  "$TOOLBIN/llvm-strip" --strip-unneeded "$WORK/build-$ABI/libtdjson.so" -o "$OUT_DIR/$ABI/libtdjson.so" 2>/dev/null \
    || "$TOOLBIN/llvm-strip" --strip-unneeded "$WORK/build-$ABI/td/libtdjson.so" -o "$OUT_DIR/$ABI/libtdjson.so"
  ls -la "$OUT_DIR/$ABI/libtdjson.so"
done
echo "== Done: $OUT_DIR"

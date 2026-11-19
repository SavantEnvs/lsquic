#!/usr/bin/env bash
#
# mayhem/build.sh — build lsquic's fuzz harnesses and its unit-test suite.
# Runs in the commit image as `mayhem` in /mayhem; re-runnable and offline (BoringSSL is prebuilt
# under /opt/toolchains/deps by mayhem/Dockerfile, zlib comes from apt).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:?the base image provides STANDALONE_FUZZ_MAIN}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
BSSL=/opt/toolchains/deps/boringssl-0.20250807.0
[ -f "$BSSL/lib/libssl.a" ] || { echo "BoringSSL not found at $BSSL" >&2; exit 1; }
[ -f src/liblsquic/ls-qpack/lsqpack.c ] && [ -f src/lshpack/lshpack.c ] \
  || { echo "git submodules missing: run git submodule update --init --recursive" >&2; exit 1; }

ssl_args=(-DLSQUIC_LIBSSL=BORINGSSL -DBORINGSSL_INCLUDE="$BSSL/include"
          -DBORINGSSL_LIB_ssl="$BSSL/lib/libssl.a" -DBORINGSSL_LIB_crypto="$BSSL/lib/libcrypto.a")

# 1) liblsquic, instrumented. Debug build type keeps assert() live (no -DNDEBUG; many upstream fixes
#    are assertion failures); LSQUIC_ASAN=OFF because the sanitizers come from SANITIZER_FLAGS via
#    EXTRA_CFLAGS (appended after upstream's -O0 -g3, so -O1 and -gdwarf-3 win).
# Four UBSan checks are relaxed (only when UBSan is on): pointer-overflow, nonnull-attribute,
# alignment (lsquic_xxhash.c deliberately reads unaligned U32s on x86: XXH_USE_UNALIGNED_ACCESS) and
# vla-bound (lsquic_qenc_hdl.c:384 declares enc_buf[capacity * 2], a zero-length VLA whenever the
# peer advertises no QPACK dynamic table, the default, so every HTTP/3 request trips it).
# ls-hpack, ls-qpack and lsquic_xxhash.c do NULL + 0 and memcpy(dst, NULL, 0) on empty arrays and
# strings (lshpack.c:236 table growth, lsqpack.c:871 empty string, lsquic_xxhash.c:261 empty name).
# Each halts within a few hundred execs on almost any input and hides everything deeper. ASan and
# the rest of UBSan stay on and halting.
UB_RELAX=""
case " $SANITIZER_FLAGS " in *undefined*) UB_RELAX="-fno-sanitize=pointer-overflow,nonnull-attribute,alignment,vla-bound" ;; esac
FUZZ_CFLAGS="$SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
EXTRA_CFLAGS="$FUZZ_CFLAGS" cmake -S . -B mayhem/build-fuzz -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS_DEBUG="$DEBUG_FLAGS" \
    -DLSQUIC_ASAN=OFF -DLSQUIC_BIN=OFF -DLSQUIC_TESTS=OFF "${ssl_args[@]}"
EXTRA_CFLAGS="$FUZZ_CFLAGS" cmake --build mayhem/build-fuzz --target lsquic -j"$MAYHEM_JOBS"
LIB=mayhem/build-fuzz/src/liblsquic/liblsquic.a

# 2) harnesses: libFuzzer binary + run-once -standalone reproducer each.
mkdir -p mayhem/build-fuzz/obj
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o mayhem/build-fuzz/obj/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o mayhem/build-fuzz/obj/standalone_main.o
INC=(-Iinclude -Isrc/liblsquic/ls-qpack -Isrc/lshpack -I"$BSSL/include")
LIBS=("$LIB" "$BSSL/lib/libssl.a" "$BSSL/lib/libcrypto.a" -lz -lm -lpthread -lstdc++)
for h in fuzz_qpack_decoder fuzz_qpack_encoder fuzz_hpack_decoder \
         fuzz_server_datagrams fuzz_server_initial fuzz_h3_loopback fuzz_h3_client fuzz_client_initial; do
    [ -f "mayhem/harnesses/$h.c" ] || continue
    $CC $FUZZ_CFLAGS "${INC[@]}" \
        -c "mayhem/harnesses/$h.c" -o "mayhem/build-fuzz/obj/$h.o"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "mayhem/build-fuzz/obj/$h.o" \
        mayhem/build-fuzz/obj/lsan_off.o "${LIBS[@]}" -o "/mayhem/$h"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS mayhem/build-fuzz/obj/standalone_main.o \
        "mayhem/build-fuzz/obj/$h.o" mayhem/build-fuzz/obj/lsan_off.o "${LIBS[@]}" \
        -o "/mayhem/$h-standalone"
done

# 3) upstream unit tests (tests/), normal flags, no sanitizers: Debug (the test framework relies on
#    assert()), LSQUIC_ASAN=OFF so upstream does not add ASan on clang.
env -u EXTRA_CFLAGS cmake -S . -B mayhem/build-tests -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" \
    -DLSQUIC_ASAN=OFF -DLSQUIC_BIN=OFF -DLSQUIC_TESTS=ON "${ssl_args[@]}"
env -u EXTRA_CFLAGS cmake --build mayhem/build-tests -j"$MAYHEM_JOBS"

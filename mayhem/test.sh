#!/usr/bin/env bash
#
# mayhem/test.sh — run lsquic's own unit-test suite (tests/, built by mayhem/build.sh into
# mayhem/build-tests with normal flags) plus known-answer checks on the transport-parameter
# decoder, and emit a CTRF report.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

B=mayhem/build-tests
[ -x "$B/tests/test_trapa" ] || { echo "test suite not built (run mayhem/build.sh)" >&2; exit 1; }

passed=0 failed=0

# 1) upstream ctest suite (assert-based unit tests: frame parsers, ACK generation, stream, H3
#    framing, QPACK handler, send controller, ...).
log="$(cd "$B" && ctest -j"$MAYHEM_JOBS" --output-on-failure 2>&1)"
echo "$log" | tail -n 25
line="$(echo "$log" | grep -E '[0-9]+% tests passed, [0-9]+ tests failed out of [0-9]+' | tail -1)"
if [ -n "$line" ]; then
  total="$(echo "$line" | sed -E 's/.* out of ([0-9]+).*/\1/')"
  nfail="$(echo "$line" | sed -E 's/.* ([0-9]+) tests failed.*/\1/')"
  passed=$(( passed + total - nfail )); failed=$(( failed + nfail ))
else
  echo "ctest produced no summary" >&2; failed=$(( failed + 1 ))
fi

# 2) known-answer tests: lsquic_tp_decode() on a real QUIC v1 client transport-parameter blob
#    (72 bytes, captured from lsquic's own ClientHello) must consume all 72 bytes; the same blob
#    truncated by 3 bytes must be rejected.
kat() {  # kat <name> <file> <expected stdout line>
  local out; out="$("$B/tests/test_trapa" -d "$2" 2>/dev/null)"
  if [ "$out" = "$3" ]; then echo "PASS $1"; passed=$(( passed + 1 ));
  else echo "FAIL $1: got '$out', want '$3'"; failed=$(( failed + 1 )); fi
}
kat tp_decode_client_v1 mayhem/test-data/tp_client_v1.bin \
    "decoded params from mayhem/test-data/tp_client_v1.bin: 72 (OK)"
kat tp_decode_truncated mayhem/test-data/tp_truncated.bin \
    "decoded params from mayhem/test-data/tp_truncated.bin: -1 (FAIL)"

emit_ctrf "cmake-ctest" "$passed" "$failed" 0

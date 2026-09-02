#!/usr/bin/env bash
# Cross-SDK Method B benchmark comparison: ans-sdk-go vs ans-sdk-rust.
#
# Self-contained: copy this one file to a fresh machine and run it. It
# clones both repos, runs every benchmark sequentially (never concurrent
# — concurrent load cross-contaminates results), and merges everything
# into results/REPORT.md.
#
#   ./run_bench_comparison.sh [workdir]     # default workdir: ~/ans-bench
#
# Prereqs: git, python3, Go >= 1.26, Rust stable. Clone auth for the
# agentnameservice org must already be set up if the repos are private.
#
# Tunables (env): SAMPLES=6 BENCHTIME=2s
#
# Method notes baked in here:
# - Each Go benchmark runs in its own process. A suite run (-bench .)
#   inflates results 2-3x: every benchmark pre-mints its fixtures
#   in-process and the GC/scavenger pressure bleeds into later timed
#   loops.
# - Go gets SAMPLES repetitions per benchmark (the merger medians them);
#   criterion does its own sampling within one run.
# - Rust runs twice: pure p256, then ring-backed verification
#   (fast-verify).

set -euo pipefail
trap 'echo "ERROR: command failed at line $LINENO: $BASH_COMMAND" >&2' ERR

WORKDIR="${1:-$HOME/ans-bench}"
SAMPLES="${SAMPLES:-6}"
BENCHTIME="${BENCHTIME:-2s}"
GO_BRANCH="spike/a2a-pop-no-mtls"     # PR #68 — pop benchmarks live here
RUST_BRANCH="feat/dpop-flavor-b"      # PR #105

GO_BENCHES=(
  SignProof
  VerifyStatusToken
  VerifyReceipt
  VerifyProof
  VerifyCaller
  VerifyCaller_NoReceipt
  VerifyCaller_Parallel
  MemoryReplayCache_Loaded
)
CRITERION_FILTER="status_token/verify|receipt/verify/2pow20|dpop/|ecdsa_p256|replay_cache"

banner() { printf '\n== %s ==\n' "$*"; }

# Run one go test benchmark; on success append its output to the results
# file, on failure print the output (which carries the reason) and stop.
go_bench() {
  local dir=$1 pkg=$2 pattern=$3 out
  if ! out=$(cd "$dir" && go test -bench "$pattern" -run '^$' \
      -benchtime "$BENCHTIME" -benchmem "$pkg" 2>&1); then
    echo "FAILED: go test -bench '$pattern' in $dir" >&2
    printf '%s\n' "$out" >&2
    exit 1
  fi
  printf '%s\n' "$out" >> "$WORKDIR/results/go-bench.txt"
}

mkdir -p "$WORKDIR/results"
cd "$WORKDIR"

banner "0/5 setup"
[ -d ans-sdk-go ] || git clone https://github.com/agentnameservice/ans-sdk-go
git -C ans-sdk-go fetch origin "$GO_BRANCH"
git -C ans-sdk-go checkout "$GO_BRANCH"
[ -d ans-sdk-rust ] || git clone https://github.com/agentnameservice/ans-sdk-rust
git -C ans-sdk-rust fetch origin "$RUST_BRANCH"
git -C ans-sdk-rust checkout "$RUST_BRANCH"

{
  uname -a
  echo "cpus: $(nproc 2>/dev/null || sysctl -n hw.ncpu)"
  go version
  rustc -V
  echo "ans-sdk-go:   $GO_BRANCH @ $(git -C ans-sdk-go rev-parse --short HEAD)"
  echo "ans-sdk-rust: $RUST_BRANCH @ $(git -C ans-sdk-rust rev-parse --short HEAD)"
  echo "samples: $SAMPLES x benchtime $BENCHTIME (Go); criterion defaults (Rust)"
} | tee results/env.txt

banner "1/5 Go pop benchmarks (one process per benchmark, $SAMPLES samples)"
: > results/go-bench.txt
(cd ans-sdk-go && go build ./pop/)
for i in $(seq "$SAMPLES"); do
  for b in "${GO_BENCHES[@]}"; do
    echo "  sample $i/$SAMPLES: $b"
    go_bench ans-sdk-go ./pop/ "^Benchmark${b}\$"
  done
done

banner "2/5 Go raw ECDSA P-256 baseline"
mkdir -p ecdsabench
cat > ecdsabench/go.mod <<'EOF'
module ecdsabench

go 1.26
EOF
cat > ecdsabench/bench_test.go <<'EOF'
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func BenchmarkP256Sign(b *testing.B) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d := sha256.Sum256([]byte("bench"))
	b.ResetTimer()
	for range b.N {
		if _, err := ecdsa.SignASN1(rand.Reader, key, d[:]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkP256Verify(b *testing.B) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d := sha256.Sum256([]byte("bench"))
	sig, _ := ecdsa.SignASN1(rand.Reader, key, d[:])
	b.ResetTimer()
	for range b.N {
		if !ecdsa.VerifyASN1(&key.PublicKey, d[:], sig) {
			b.Fatal("bad sig")
		}
	}
}
EOF
# No shared fixtures between these two — one process for both is fine.
for i in $(seq "$SAMPLES"); do
  echo "  sample $i/$SAMPLES: P256Sign+P256Verify"
  go_bench ecdsabench . '^BenchmarkP256'
done

banner "3/5 Rust criterion, pure p256"
(cd ans-sdk-rust && cargo bench -p ans-verify --features scitt,test-support \
  -- "$CRITERION_FILTER") 2>&1 | tee results/rust-pure.txt

banner "4/5 Rust criterion, ring (fast-verify)"
(cd ans-sdk-rust && cargo bench -p ans-verify --features scitt,test-support,fast-verify \
  -- "$CRITERION_FILTER") 2>&1 | tee results/rust-ring.txt

banner "5/5 report"
python3 ans-sdk-rust/scripts/merge_bench_report.py \
  results/go-bench.txt results/rust-pure.txt results/rust-ring.txt \
  > results/REPORT.md

{
  echo '```'
  cat results/env.txt
  echo '```'
  echo
  cat results/REPORT.md
} > results/REPORT.full.md
mv results/REPORT.full.md results/REPORT.md

cat results/REPORT.md
echo
echo "Report: $WORKDIR/results/REPORT.md"
echo "Criterion HTML: $WORKDIR/ans-sdk-rust/target/criterion/report/index.html"

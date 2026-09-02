#!/usr/bin/env python3
"""Merge Go `go test -bench` output and Rust criterion output into one table.

Usage: merge_report.py go-bench.txt rust-pure.txt rust-ring.txt > REPORT.md

go-bench.txt   — concatenated output of the per-process Go benchmark runs
rust-pure.txt  — criterion stdout, features scitt,test-support
rust-ring.txt  — criterion stdout, features scitt,test-support,fast-verify

Multiple samples of the same Go benchmark are reduced to the median.
Criterion lines report [low mid high]; the mid estimate is used.
"""

import re
import statistics
import sys

# Go benchmark name -> (row label, criterion id)
ROWS = [
    ("BenchmarkSignProof", "Mint DPoP proof", "dpop/sign"),
    ("BenchmarkVerifyStatusToken", "Status token verify", "status_token/verify"),
    ("BenchmarkVerifyReceipt", "Receipt verify (2^20 log)", "receipt/verify/2pow20_entries"),
    ("BenchmarkVerifyProof", "DPoP proof verify", "dpop/verify_proof"),
    ("BenchmarkVerifyCaller", "Caller: full (3 proofs)", "dpop/verify_caller_cold"),
    ("BenchmarkVerifyCaller_NoReceipt", "Caller: no receipt", "dpop/verify_caller_no_receipt"),
    ("BenchmarkVerifyCaller_Parallel", "Caller: parallel (wall/req)", "dpop/verify_caller_parallel"),
    ("BenchmarkMemoryReplayCache_Loaded", "Replay cache @100k live", "replay_cache/check_and_store_at_100k"),
    # Rust-only tiers (Go has no artifact cache)
    (None, "Caller: warm (receipt cached)", "dpop/verify_caller_warm"),
    (None, "Caller: hot (both cached)", "dpop/verify_caller_hot"),
    # Optional micro baselines (Go side comes from the ecdsabench scratch module)
    ("BenchmarkP256Sign", "raw ECDSA P-256 sign", "ecdsa_p256/sign_prehash"),
    ("BenchmarkP256Verify", "raw ECDSA P-256 verify", "ecdsa_p256/verify"),
]

UNIT = {"ns": 1e-3, "µs": 1.0, "us": 1.0, "ms": 1e3, "s": 1e6}


def parse_go(path):
    """name -> median ns/op over all samples, as µs."""
    samples = {}
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^(Benchmark\w+)-\d+\s+\d+\s+([\d.]+) ns/op", line)
        if m:
            samples.setdefault(m.group(1), []).append(float(m.group(2)))
    return {name: statistics.median(v) / 1000.0 for name, v in samples.items()}


def parse_criterion(path):
    """criterion id -> mid estimate in µs. Handles the name being on its own
    line (long ids) or sharing the line with `time:`."""
    out, pending = {}, None
    rx_time = re.compile(
        r"time:\s+\[[\d.]+ (?:ns|µs|us|ms|s) ([\d.]+) (ns|µs|us|ms|s) [\d.]+"
    )
    rx_name = re.compile(r"^([\w/]+[\w])\s*(.*)$")
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        m = rx_time.search(line)
        if m:
            name = pending if line.lstrip().startswith("time:") else None
            if name is None:
                nm = rx_name.match(line)
                name = nm.group(1) if nm else pending
            if name:
                out[name] = float(m.group(1)) * UNIT[m.group(2)]
            pending = None
        else:
            nm = rx_name.match(line.strip())
            if nm and "/" in nm.group(1) and not nm.group(2):
                pending = nm.group(1)
    return out


def fmt(v):
    return f"{v:,.1f} µs" if v is not None else "—"


def main():
    go = parse_go(sys.argv[1])
    pure = parse_criterion(sys.argv[2])
    ring = parse_criterion(sys.argv[3])

    print("| Benchmark | Go | Rust `p256` (pure) | Rust ring (`fast-verify`) |")
    print("|---|---|---|---|")
    for go_name, label, crit_id in ROWS:
        g = go.get(go_name) if go_name else None
        p, r = pure.get(crit_id), ring.get(crit_id)
        if g is None and p is None and r is None:
            continue
        print(f"| {label} | {fmt(g)} | {fmt(p)} | {fmt(r)} |")


if __name__ == "__main__":
    main()

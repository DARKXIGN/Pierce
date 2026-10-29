#!/usr/bin/env python3
"""Regression guard: compare a short CI run against the committed full measurement.

  lab/ci_check.py REFERENCE.csv RUN.csv [REFERENCE.csv RUN.csv ...]

Both files are per-attempt CSVs with natA, natB, success (and optionally path). For every NAT
combination the reference gives a success rate from >=100 attempts; the CI run has only a few
(e.g. 10), so its rate is noisy. A cell fails only if the CI result is implausibly low:

  p = Wilson 95% lower bound of the reference rate (so 100/100 counts as ~96%, not 100%)
  fail if P(X <= k | n, p) < 0.01, X ~ Binomial(n, p), k/n the CI result

With 10 attempts against a 100% reference that tolerates two failures and fails on three. Cells
that got better are fine. If the run has a path column, any attempt with path "none" (neither
direct nor relay) also fails the check, when the reference had none in that cell.

Exit code 0 if everything passes, 1 otherwise; prints one line per cell that failed.
"""
import csv
import math
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from report import wilson  # noqa: E402

ALPHA = 0.01


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p)."""
    return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1))


def load(path: str):
    """{(natA, natB): [successes, attempts, attempts with path "none"]}"""
    cells = defaultdict(lambda: [0, 0, 0])
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            c = cells[(row["natA"], row["natB"])]
            c[1] += 1
            c[0] += row["success"].strip() == "1"
            c[2] += (row.get("path") or "").strip() == "none"
    return cells


def check(reference: str, run: str) -> list[str]:
    ref, got = load(reference), load(run)
    problems = []
    for key, (k, n, none) in sorted(got.items()):
        if key not in ref:
            problems.append(f"{run}: {key[0]} x {key[1]}: not in {reference}")
            continue
        rk, rn, rnone = ref[key]
        p = wilson(rk, rn)[0]
        tail = binom_cdf(k, n, p)
        if tail < ALPHA:
            problems.append(f"{run}: {key[0]} x {key[1]}: {k}/{n} direct, reference {rk}/{rn} "
                            f"(P = {tail:.4f} < {ALPHA})")
        if none and not rnone:
            problems.append(f"{run}: {key[0]} x {key[1]}: {none}/{n} attempts connected over "
                            f"neither path, reference had none")
    return problems


def main() -> None:
    args = sys.argv[1:]
    if not args or len(args) % 2:
        sys.exit(__doc__.strip().splitlines()[2])
    problems = []
    for reference, run in zip(args[0::2], args[1::2]):
        problems += check(reference, run)
    for p in problems:
        print("FAIL", p)
    if not problems:
        print(f"OK: {len(args) // 2} run(s) consistent with the reference measurements")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()

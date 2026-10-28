#!/usr/bin/env python3
"""Turn per-attempt CSVs into the README's NAT A x NAT B tables. Never edit those tables by hand.

  lab/report.py results/stage2_baseline.csv --section stage2 [--readme README.md]
  lab/report.py results/stage2_delay.csv --section delay --by delay_ms --readme README.md

Input: one row per attempt with at least `natA,natB,success` (success is 0/1). If the time column
(default `time_to_connect_ms`, see --time-col) exists, a second table with median / p95 of the
successful attempts is added. If a `path` column contains "relay", a third table gives the share
of attempts that ended on the relay. Several CSVs may be given; their rows are pooled.

Output: Markdown. With --readme, it replaces the text between
`<!-- report:<section>:start -->` and `<!-- report:<section>:end -->` in that file; otherwise it is
printed to stdout.

With --upgrade the input is results/stage3_upgrade.csv (natA,natB,attempt,initial_path,upgrade_ms)
and the output is one row per NAT pair: how many connections started on the relay, how many of
those upgraded to a direct path [Wilson 95% CI], and median / p95 upgrade time.

With --by COLUMN the table has one row per NAT pair that occurs in the data and one column per
value of COLUMN (e.g. the extra delay), instead of the NAT A x NAT B grid.

Success rates come with a Wilson 95% score interval, e.g. `87% [79–92]`: unlike the plain
p ± 1.96·sqrt(p(1-p)/n) interval it stays inside 0–100% and behaves well at 0% and 100%.
"""
import argparse
import csv
import math
import re
import sys
from collections import defaultdict

NAT_TYPES = ["full", "restricted", "port-restricted", "symmetric-random", "symmetric-sequential"]
Z95 = 1.959963984540054  # standard normal quantile for a two-sided 95% interval


def wilson(successes: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion, as fractions in [0, 1]."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def percentile(sorted_values: list[float], q: float) -> float:
    """Nearest-rank percentile (q in 0..100) of an already sorted, non-empty list."""
    rank = max(1, math.ceil(q / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def load(paths: list[str], time_col: str, by: str | None = None):
    """Returns {key: [successes, attempts, [times of successful attempts], relayed]}, has_time.
    key is (natA, natB), or (natA, natB, value of `by`) when `by` is given."""
    cells = defaultdict(lambda: [0, 0, [], 0])
    has_time = False
    for path in paths:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            missing = {"natA", "natB", "success"} - set(reader.fieldnames or [])
            if by:
                missing |= {by} - set(reader.fieldnames or [])
            if missing:
                sys.exit(f"{path}: missing column(s) {', '.join(sorted(missing))}")
            has_time |= time_col in reader.fieldnames
            for row in reader:
                key = (row["natA"], row["natB"]) + ((row[by],) if by else ())
                cell = cells[key]
                cell[1] += 1
                if (row.get("path") or "").strip() == "relay":
                    cell[3] += 1
                if row["success"].strip() == "1":
                    cell[0] += 1
                    t = (row.get(time_col) or "").strip()
                    if t:
                        cell[2].append(float(t))
    return cells, has_time


def table(cells, fmt) -> str:
    lines = ["| NAT A \\ NAT B | " + " | ".join(NAT_TYPES) + " |",
             "|---|" + "---|" * len(NAT_TYPES)]
    for a in NAT_TYPES:
        row = [fmt(cells[(a, b)]) if (a, b) in cells else "—" for b in NAT_TYPES]
        lines.append(f"| {a} | " + " | ".join(row) + " |")
    return "\n".join(lines)


def pivot_table(cells, by: str, fmt) -> str:
    """Rows: NAT pairs in the data (in NAT_TYPES order). Columns: values of `by`, numerically."""
    def num(v):
        try:
            return (0, float(v))
        except ValueError:
            return (1, v)
    values = sorted({k[2] for k in cells}, key=num)
    order = {t: i for i, t in enumerate(NAT_TYPES)}
    pairs = sorted({k[:2] for k in cells}, key=lambda p: (order.get(p[0], 99), order.get(p[1], 99)))
    lines = ["| NAT A × NAT B | " + " | ".join(f"{by} = {v}" for v in values) + " |",
             "|---|" + "---|" * len(values)]
    for a, b in pairs:
        row = [fmt(cells[(a, b, v)]) if (a, b, v) in cells else "—" for v in values]
        lines.append(f"| {a} × {b} | " + " | ".join(row) + " |")
    return "\n".join(lines)


def fmt_rate(cell) -> str:
    k, n = cell[0], cell[1]
    lo, hi = wilson(k, n)
    return f"{round(100 * k / n)}% [{round(100 * lo)}–{round(100 * hi)}]"


def fmt_relay(cell) -> str:
    return fmt_rate([cell[3], cell[1]])


def fmt_time(cell) -> str:
    times = sorted(cell[2])
    if not times:
        return "—"
    return f"{percentile(times, 50):.0f} / {percentile(times, 95):.0f}"


def render(cells, has_time: bool, time_label: str, by: str | None = None) -> str:
    counts = sorted({c[1] for c in cells.values()})
    n_text = str(counts[0]) if len(counts) == 1 else f"{counts[0]}–{counts[-1]}"
    grid = (lambda fmt: pivot_table(cells, by, fmt)) if by else (lambda fmt: table(cells, fmt))
    parts = [f"Success rate [Wilson 95% CI], n = {n_text} attempts per cell.", "", grid(fmt_rate)]
    if has_time:
        parts += ["", f"{time_label}, median / p95 in ms (successful attempts only).", "",
                  grid(fmt_time)]
    if any(c[3] for c in cells.values()):
        parts += ["", "Relay usage: attempts that fell back to the relay [Wilson 95% CI].", "",
                  grid(fmt_relay)]
    return "\n".join(parts)


def render_upgrade(paths: list[str]) -> str:
    rows = defaultdict(lambda: [0, 0, []])  # (natA, natB) -> [relayed, upgraded, [ms]]
    for path in paths:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            missing = {"natA", "natB", "initial_path", "upgrade_ms"} - set(reader.fieldnames or [])
            if missing:
                sys.exit(f"{path}: missing column(s) {', '.join(sorted(missing))}")
            for row in reader:
                if row["initial_path"].strip() != "relay":
                    continue
                r = rows[(row["natA"], row["natB"])]
                r[0] += 1
                ms = row["upgrade_ms"].strip()
                if ms:
                    r[1] += 1
                    r[2].append(float(ms))
    lines = ["| NAT A × NAT B | started on relay | upgraded to direct | upgrade time, median / p95 ms |",
             "|---|---|---|---|"]
    order = {t: i for i, t in enumerate(NAT_TYPES)}
    for (a, b) in sorted(rows, key=lambda p: (order.get(p[0], 99), order.get(p[1], 99))):
        relayed, upgraded, times = rows[(a, b)]
        lines.append(f"| {a} × {b} | {relayed} | {fmt_rate([upgraded, relayed])} | "
                     f"{fmt_time([0, 0, times])} |")
    return "\n".join(lines)


def splice(readme: str, section: str, body: str) -> str:
    start, end = f"<!-- report:{section}:start -->", f"<!-- report:{section}:end -->"
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.S)
    if not pattern.search(readme):
        sys.exit(f"markers for section '{section}' not found")
    return pattern.sub(lambda _: f"{start}\n{body}\n{end}", readme)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--section", default="results")
    ap.add_argument("--readme")
    ap.add_argument("--time-col", default="time_to_connect_ms")
    ap.add_argument("--time-label", default="Time to connect")
    ap.add_argument("--by", help="pivot on this column instead of the NAT A x NAT B grid")
    ap.add_argument("--upgrade", action="store_true", help="input is stage3_upgrade.csv")
    args = ap.parse_args()

    if args.upgrade:
        body = render_upgrade(args.csv)
    else:
        cells, has_time = load(args.csv, args.time_col, args.by)
        if not cells:
            sys.exit("no rows")
        body = render(cells, has_time, args.time_label, args.by)
    if args.readme:
        with open(args.readme) as f:
            text = f.read()
        with open(args.readme, "w") as f:
            f.write(splice(text, args.section, body))
        print(f"updated section '{args.section}' in {args.readme}")
    else:
        print(body)


if __name__ == "__main__":
    main()

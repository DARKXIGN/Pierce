# Pierce

A WireGuard-based mesh VPN agent. The goal is to raise the **direct connection success rate** between two devices behind NAT, so traffic falls back to a relay less often.

> Why not just use Tailscale? Tailscale works well, but its NAT traversal is a black box to its users: I wanted to see *why* a connection ends up on a relay and measure how much each technique (hole punching, port prediction, birthday probing) actually helps, so I built the traversal engine myself and test it in a reproducible NAT lab.

## Results

All tables are generated from the per-attempt CSVs in `results/` by `lab/report.py`; do not edit them by hand. Success rates come with Wilson 95% confidence intervals.

### Stage 1: NAT type detection

Can the C++ detector (`nat_detect`) tell the five lab NAT types apart? One attempt = both peers run the detector at the same time; success = both sides classified as configured. NAT A is the row, NAT B the column.

<!-- report:stage1:start -->
Success rate [Wilson 95% CI], n = 100 attempts per cell.

| NAT A \ NAT B | full | restricted | port-restricted | symmetric-random | symmetric-sequential |
|---|---|---|---|---|---|
| full | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| restricted | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| port-restricted | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| symmetric-random | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| symmetric-sequential | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |

Detection time, median / p95 in ms (successful attempts only).

| NAT A \ NAT B | full | restricted | port-restricted | symmetric-random | symmetric-sequential |
|---|---|---|---|---|---|
| full | 0 / 0 | 198 / 198 | 397 / 397 | 0 / 0 | 0 / 0 |
| restricted | 198 / 198 | 198 / 198 | 397 / 397 | 198 / 198 | 198 / 198 |
| port-restricted | 397 / 397 | 397 / 397 | 397 / 397 | 397 / 397 | 397 / 397 |
| symmetric-random | 0 / 0 | 198 / 198 | 397 / 397 | 0 / 0 | 0 / 0 |
| symmetric-sequential | 0 / 0 | 198 / 198 | 397 / 397 | 0 / 0 | 0 / 0 |
<!-- report:stage1:end -->

### Stage 2+: direct connection success rate

Direct connection success rate and time to connect per NAT combination, ≥100 attempts each. Baseline (stage 2) → improved (stage 3). Not measured yet.

<!-- report:stage2:start -->
<!-- report:stage2:end -->

## Build

```sh
cmake -B build -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build
ctest --test-dir build
```

On Ubuntu you can skip vcpkg for now: `sudo apt install cmake g++ libgtest-dev`, then `cmake -B build` without the toolchain file.

## NAT lab (Linux, root)

```sh
sudo ./lab/setup.sh full symmetric-random   # NAT A, NAT B: full | restricted | port-restricted | symmetric-random | symmetric-sequential
sudo ./lab/check_ping.sh
sudo ./lab/check_nat.sh full symmetric-random
sudo ./lab/teardown.sh
sudo ./lab/run_matrix.sh                    # all 5×5 combinations -> results/*.csv
python3 lab/report.py results/stage1_nat_detect.csv --section stage1 --readme README.md \
  --time-col detect_ms --time-label "Detection time"
```

## STUN and NAT type detection

```sh
build/stun_server --ip 203.0.113.10 --alt-ip 203.0.113.11            # ports 3478 and 3479 on both IPs
build/nat_detect --server 203.0.113.10:3478 --alt-ip 203.0.113.11    # prints "<type>,<ms>"
```

The detector first sends Binding requests from one socket to three addresses of the server (primary, other IP, other port). Different public ports mean a symmetric NAT: the same small step each time (e.g. +1, +1) is `symmetric-sequential`, anything else `symmetric-random`. Same port means a cone NAT, and two more tests on fresh sockets ask the server (CHANGE-REQUEST, RFC 5780) to answer from its other IP, then from its other port: the first getting through means `full`, the second `restricted`, neither `port-restricted`.

The filtering tests need one server with two IPs, which the lab has. Two separate STUN servers (the real deployment) are enough to tell cone from symmetric, but not the cone types apart.

## Documentation

- `lab/README.md` — NAT lab topology, how each NAT type is built, the userspace NAT

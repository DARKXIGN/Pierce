# Pierce

A WireGuard-based mesh VPN agent. The goal is to raise the **direct connection success rate** between two devices behind NAT, so traffic falls back to a relay less often.

> Why not just use Tailscale? Tailscale works well, but its NAT traversal is a black box to its users: I wanted to see *why* a connection ends up on a relay and measure how much each technique (hole punching, port prediction, birthday probing) actually helps, so I built the traversal engine myself and test it in a reproducible NAT lab.

## Results

Direct connection success rate per NAT combination, ≥100 attempts each, with Wilson 95% confidence intervals, plus time to connect. Generated from `results/*.csv` by `lab/report.py` — do not edit the table by hand.

<!-- report:start -->
| NAT A \ NAT B | full | restricted | port-restricted | symmetric-random | symmetric-sequential |
|---|---|---|---|---|---|
| full | — | — | — | — | — |
| restricted | — | — | — | — | — |
| port-restricted | — | — | — | — | — |
| symmetric-random | — | — | — | — | — |
| symmetric-sequential | — | — | — | — | — |
<!-- report:end -->

Baseline (stage 2) → improved (stage 3). Raw per-attempt data in `results/`.

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
sudo ./lab/run_matrix.sh                    # all 5×5 combinations
```

## Documentation

- `lab/README.md` — NAT lab topology and how each NAT type is built

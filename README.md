# Pierce

A WireGuard-based mesh VPN agent. The goal is to raise the **direct connection success rate** between two devices behind NAT, so traffic falls back to a relay less often.

> Motivation: (one line here — e.g., when using my home server and OCI from a phone hotspot, connections kept falling back to a relay, so I wanted to fix it myself)

## Results (filled in after measurement)

| NAT A \ NAT B   | full cone | restricted | port-restricted | symmetric |
| --------------- | --------- | ---------- | --------------- | --------- |
| full cone       | —         | —          | —               | —         |
| restricted      | —         | —          | —               | —         |
| port-restricted | —         | —          | —               | —         |
| symmetric       | —         | —          | —               | —         |

Baseline (stage 2) → improved (stage 3) success rate. Details in `results/`.

## Build

```sh
cmake -B build -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build
ctest --test-dir build
```

On Ubuntu you can skip vcpkg for now: `sudo apt install cmake g++ libgtest-dev`, then `cmake -B build` without the toolchain file.

## NAT lab (Linux, root)

```sh
sudo ./lab/setup.sh full symmetric   # NAT type for A and B: full | restricted | port-restricted | symmetric
sudo ./lab/check_ping.sh
sudo ./lab/check_nat.sh full symmetric
sudo ./lab/teardown.sh
sudo ./lab/run_matrix.sh             # all 4×4 combinations
```

## Documentation

- `lab/README.md` — NAT lab topology and how each NAT type is built

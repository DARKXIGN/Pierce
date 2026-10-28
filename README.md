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

### Stage 2: direct connection baseline

Plain hole punching: host and server-reflexive candidates, RTT-compensated simultaneous probes, peer-reflexive candidates learned from incoming probes, 3 s cap, no relay. One attempt = both agents start at the same time; success = both received an authenticated probe response. Time to connect runs from the start of signaling to that first response (slower side). Stage 3 (port prediction, birthday probing) is measured against this table.

<!-- report:stage2:start -->
<!-- report:stage2:end -->

#### Asymmetric delay

Extra one-way delay on NAT A's internet link only (`tc netem`), to check that the RTT-compensated punch time keeps working when one peer is far away.

<!-- report:delay:start -->
Not measured yet: needs `tc netem` (`sudo ./lab/run_stage2.sh delay` on OCI).
<!-- report:delay:end -->

#### Coordination server outage

`sudo ./lab/check_coord_outage.sh` connects two peers, kills the coordination and STUN servers, then requires 10 s of keepalives (every 500 ms) to keep getting answered on both sides.

## Build

```sh
cmake -B build -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build
ctest --test-dir build
```

On Ubuntu 24.04 you can skip vcpkg and use the distro packages, then `cmake -B build` without the toolchain file:

```sh
sudo apt install cmake g++ libgtest-dev libssl-dev libsqlite3-dev \
  libgrpc++-dev libprotobuf-dev protobuf-compiler protobuf-compiler-grpc iproute2
```

## NAT lab (Linux, root)

```sh
sudo ./lab/setup.sh full symmetric-random   # NAT A, NAT B: full | restricted | port-restricted | symmetric-random | symmetric-sequential
sudo ./lab/check_ping.sh
sudo ./lab/check_nat.sh full symmetric-random
sudo ./lab/teardown.sh
sudo ./lab/run_matrix.sh                    # all 5×5 combinations -> results/*.csv
python3 lab/report.py results/stage1_nat_detect.csv --section stage1 --readme README.md \
  --time-col detect_ms --time-label "Detection time"

sudo ./lab/run_stage2.sh baseline           # stage 2, all 5×5 combinations -> results/stage2_baseline.csv (~1 h)
sudo ./lab/run_stage2.sh delay              # one-sided extra delay -> results/stage2_delay.csv (needs tc netem)
sudo ./lab/check_coord_outage.sh            # peers keep working after the coordination server dies
python3 lab/report.py results/stage2_baseline.csv --section stage2 --readme README.md
python3 lab/report.py results/stage2_delay.csv --section delay --by delay_ms --readme README.md
```

## STUN and NAT type detection

```sh
build/stun_server --ip 203.0.113.10 --alt-ip 203.0.113.11            # ports 3478 and 3479 on both IPs
build/nat_detect --server 203.0.113.10:3478 --alt-ip 203.0.113.11    # prints "<type>,<ms>"
```

The detector first sends Binding requests from one socket to three addresses of the server (primary, other IP, other port). Different public ports mean a symmetric NAT: the same small step each time (e.g. +1, +1) is `symmetric-sequential`, anything else `symmetric-random`. Same port means a cone NAT, and two more tests on fresh sockets ask the server (CHANGE-REQUEST, RFC 5780) to answer from its other IP, then from its other port: the first getting through means `full`, the second `restricted`, neither `port-restricted`.

The filtering tests need one server with two IPs, which the lab has. Two separate STUN servers (the real deployment) are enough to tell cone from symmetric, but not the cone types apart.

## Hole punching (stage 2)

```sh
build/pierce-coord --listen 203.0.113.10:50051
build/pierce-agent --coord 203.0.113.10:50051 --stun 203.0.113.10:3478 --id A --peer B
# prints: success,time_to_connect_ms,probes_sent,path,remote   e.g. 1,44,3,direct,203.0.113.2:42790
```

1. The agent opens **one** UDP socket and uses it for everything: STUN, probes, and later WireGuard. NAT mappings belong to a socket, so the public address STUN reports is only useful if the probes leave from the same socket.
2. Candidates: every local IPv4 address (host) plus the STUN-reported public address (server-reflexive), with RFC 8445 priorities.
3. Signaling (`proto/coord.proto`, one bidirectional gRPC stream per agent): Register, Candidates. Once both peers are there, the server pings each over its stream, then sends the peer's candidates, a fresh 32-byte session key and `PunchIn{delay_ms}` with `delay_i = X − RTT_i/2`, `X = max(RTT_A, RTT_B)/2 + 20 ms`, so both peers start at the same moment without synchronized clocks.
4. Probing: one request every 20 ms, round robin over the peer's candidates. Every probe carries an 8-byte HMAC-SHA256 with the session key; anything else is dropped, and probes only ever go to IPs from signaling. A valid request from an unknown port of a known IP becomes a peer-reflexive candidate and is probed right away. That is how a peer behind a symmetric NAT gets reached.
5. Success: an authenticated response to one of our requests. Give up after 3 s (stage 3 then falls back to a relay).

## Documentation

- `lab/README.md` — NAT lab topology, how each NAT type is built, the userspace NAT

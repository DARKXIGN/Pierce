# NAT lab

Network namespaces create 2 peers, 2 NAT routers, an "internet" bridge and an observer host with two public IPs. Four NAT types are reproduced with nftables, the fifth (`symmetric-sequential`) with a small C++ userspace NAT. Linux and root required; build first (`cmake -B build && cmake --build build`) so `build/usernat` exists.

```
peerA 10.0.1.2 -- natA 10.0.1.1 | 203.0.113.1 --+
                                                |  bridge br0 (netns pierce-inet)
peerB 10.0.2.2 -- natB 10.0.2.1 | 203.0.113.2 --+
                                                |
                 obs 203.0.113.10, 203.0.113.11 +   two "public servers" (STUN later, self-check now)
```

Everything, including the bridge, lives in its own namespace. The host network, Docker and Nginx Proxy Manager are never touched, and `teardown.sh` removes every trace by deleting the namespaces.

## Usage
```sh
sudo ./lab/setup.sh full symmetric-random       # natA type, natB type
sudo ./lab/check_ping.sh                        # basic reachability
sudo ./lab/check_nat.sh full symmetric-random   # black-box NAT behavior check
sudo ./lab/teardown.sh

sudo ./lab/run_matrix.sh                        # all 5×5 combinations → results/lab_selfcheck.csv,
                                                #   results/stage1_nat_detect.csv (ATTEMPTS=100 per combination)
```

## NAT types
Terms from RFC 4787: *mapping* decides which public port an internal socket gets; *filtering* decides who may send in.

| Type | Mapping | Inbound filtering | Implementation |
|---|---|---|---|
| `full` | endpoint-independent | none | `masquerade` + DNAT all inbound UDP to the LAN host |
| `restricted` | endpoint-independent | remote IPs this ip:port has sent to | same DNAT + dynamic set `contacted` (internal ip . port . remote ip) |
| `port-restricted` | endpoint-independent | remote IP:port pairs this ip:port has sent to | `masquerade`, only `ct state established` |
| `symmetric-random` | endpoint-dependent, random port per destination | remote IP:port pairs | `masquerade random`, only `ct state established` |
| `symmetric-sequential` | endpoint-dependent, next port in sequence per destination | remote IP:port pairs | C++ userspace NAT `lab/usernat/` (see below; `setup.sh` exits with code 3 if `build/usernat` is missing) |

Approximations to be aware of:
- Endpoint-independent mapping relies on Linux masquerade keeping the source port when it is free. With one LAN host and no port collisions this always holds, so public port = internal port.
- `full`/`restricted` DNAT inbound UDP to the single LAN host on the same port. Fine for a one-host LAN, not a general NAT.
- `symmetric-random` picks **random** ports. Many real symmetric NATs allocate sequentially, which is what `symmetric-sequential` models.
- Mapping and `contacted` entries expire after the conntrack UDP timeout / 120 s.
- Unsolicited UDP to a router's own WAN address is dropped in the `input` hook. Without that, Linux would deliver it locally, answer with ICMP port unreachable and confirm a conntrack entry for it. If the LAN host then sends to the same remote, masquerade sees the clash and picks another public port. An early probe from the peer would make the cone NAT endpoint-dependent. Real NATs drop such packets silently.

## Userspace NAT (`lab/usernat/`)
nftables cannot hand out public ports in sequence, so `symmetric-sequential` is a ~250-line C++ program running in the NAT namespace:

- The kernel keeps NATing everything except UDP (ping still works). For UDP, nftables turns off conntrack (`notrack`) and drops it in `forward`/`input`.
- `usernat` reads UDP from `AF_PACKET` sockets on the LAN and WAN interfaces. A packet socket gets its copy before netfilter drops the original.
- LAN → WAN: each new (internal ip:port, remote ip:port) pair gets the next public port (`--step`, default +1, from 20000). The source is rewritten, checksums recomputed, and the packet sent from a raw IP socket.
- WAN → LAN: accepted only from the exact remote ip:port the mapping was made for (address-and-port-dependent filtering), then the destination is rewritten to the LAN host.
- Mappings idle longer than `--lifetime` (default 120 s) expire; the sequence keeps going instead of reusing the freed port.

`setup.sh` starts it with `USERNAT_LIFETIME` / `USERNAT_STEP` from the environment and logs to `/tmp/pierce-usernat-<ns>.log` (`-v` for per-packet lines). The mapping logic and packet rewriting live in `nat_table.cpp` / `packet.cpp` and are unit tested in `tests/usernat_test.cpp`.

## Stage 2 runs
- `run_stage2.sh baseline` brings the lab up per combination, starts `stun_server` and `pierce-coord` in `obs`, and runs both agents `ATTEMPTS` (100) times. It writes one row per attempt to `results/stage2_baseline.csv`.
- `run_stage2.sh delay` does the same for `DELAY_PAIRS` with `tc qdisc ... netem delay` on natA's WAN link (`DELAYS`, default 0/50/100/200 ms) and writes `results/stage2_delay.csv`. It needs the `sch_netem` kernel module; the script checks first and says what to install.
- `run_stage2.sh stage3` runs the 5×5 matrix with the stage 3 techniques and two relays in `obs` (`203.0.113.10:3480`, `203.0.113.11:3480`, secret generated per run) → `results/stage3_improved.csv`, where `path` is `direct`, `relay` or `none`.
- `run_stage2.sh upgrade` holds connections for `UPGRADE_HOLD` (16) seconds with a direct retry every `UPGRADE_RETRY_MS` (5000) for `UPGRADE_PAIRS` → `results/stage3_upgrade.csv` (`natA,natB,attempt,initial_path,upgrade_ms`).
- `check_coord_outage.sh [natA] [natB]` connects two peers, kills the coordination and STUN servers (the relay stays up) and checks 10 s of keepalives. With `symmetric-random symmetric-random` the path is relayed.

## Stage 4 runs
- `run_stage4.sh` adds a persistent TUN device `pierce0` in each peer namespace (10.99.0.1 / 10.99.0.2, MTU 1420), generates WireGuard keys with `pierce-wgkey`, and runs both agents with `--tun`. From peerA it measures 50 pings and a 5 s iperf3 transfer per run → `results/stage4_lab.csv` (`natA,natB,run,path,ping_avg_ms,ping_loss_pct,iperf_mbps`). Needs `iperf3` and `tcpdump`.
- On relayed runs it captures the relay port in `obs` and ICMP on peerA's `pierce0`: the ping marker must be in the second capture and never in the first.

## CI
`ci.sh` runs `run_matrix.sh` and `run_stage2.sh stage3` with `CI_ATTEMPTS` (10) attempts per combination, plus `check_coord_outage.sh` for a direct and a relayed path. `ci_check.py` then compares the run with the committed results in `results/`: a cell fails if its count is implausibly low (one-sided binomial test, p < 0.01, against the Wilson lower bound of the 100-attempt reference), or if attempts reach neither a direct path nor the relay.

## Self-check (`check_nat.sh`, `natcheck.py`)
A small Python UDP tester that proves the lab behaves as configured, independent of Pierce's own C++ STUN code (so the detector is not validated against itself). A server in `obs` listens on `.10:3478`, `.10:3479` and `.11:3478`; the client in a peer namespace:

1. asks `.10:3478`, `.11:3478` and `.10:3479` for its public port from one socket — ports differ → symmetric; same small step between the three (e.g. +1, +1) → `symmetric-sequential`, otherwise `symmetric-random`
2. from a fresh socket, asks `.10:3478` for its mapping, then asks the server to send to it from another IP — arrives → `full`
3. same, from another port on the same IP — arrives → `restricted`, otherwise `port-restricted`

## Last run
5×5 matrix: all 25 combinations passed the self-check (ping OK, both sides detected as configured), including the 9 with `symmetric-sequential`, and the C++ detector classified both sides correctly in 2500/2500 attempts (100 per combination). Linux 6.18 sandbox, Ubuntu 24.04 userland; re-run on OCI before ticking the roadmap boxes.

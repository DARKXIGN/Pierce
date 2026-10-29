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
Success rate [Wilson 95% CI], n = 100 attempts per cell.

| NAT A \ NAT B | full | restricted | port-restricted | symmetric-random | symmetric-sequential |
|---|---|---|---|---|---|
| full | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| restricted | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| port-restricted | 100% [96–100] | 100% [96–100] | 100% [96–100] | 0% [0–4] | 0% [0–4] |
| symmetric-random | 100% [96–100] | 100% [96–100] | 0% [0–4] | 0% [0–4] | 0% [0–4] |
| symmetric-sequential | 100% [96–100] | 100% [96–100] | 0% [0–4] | 0% [0–4] | 0% [0–4] |

Time to connect, median / p95 in ms (successful attempts only).

| NAT A \ NAT B | full | restricted | port-restricted | symmetric-random | symmetric-sequential |
|---|---|---|---|---|---|
| full | 42 / 43 | 43 / 83 | 43 / 83 | 43 / 43 | 43 / 43 |
| restricted | 43 / 83 | 43 / 83 | 43 / 83 | 43 / 83 | 43 / 83 |
| port-restricted | 43 / 83 | 82 / 83 | 82 / 83 | — | — |
| symmetric-random | 43 / 43 | 43 / 83 | — | — | — |
| symmetric-sequential | 43 / 43 | 43 / 83 | — | — | — |
<!-- report:stage2:end -->

#### Asymmetric delay

Extra one-way delay on NAT A's internet link only (`tc netem`), to check that the RTT-compensated punch time keeps working when one peer is far away.

<!-- report:delay:start -->
Success rate [Wilson 95% CI], n = 100 attempts per cell.

| NAT A × NAT B | delay_ms = 0 | delay_ms = 50 | delay_ms = 100 | delay_ms = 200 |
|---|---|---|---|---|
| full × full | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| port-restricted × port-restricted | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| symmetric-random × restricted | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |

Time to connect, median / p95 in ms (successful attempts only).

| NAT A × NAT B | delay_ms = 0 | delay_ms = 50 | delay_ms = 100 | delay_ms = 200 |
|---|---|---|---|---|
| full × full | 43 / 43 | 468 / 468 | 893 / 893 | 1743 / 1743 |
| port-restricted × port-restricted | 82 / 83 | 468 / 468 | 893 / 893 | 1743 / 1744 |
| symmetric-random × restricted | 43 / 83 | 493 / 493 | 943 / 943 | 1843 / 1844 |
<!-- report:delay:end -->

#### Coordination server outage

`sudo ./lab/check_coord_outage.sh` connects two peers, kills the coordination and STUN servers, then requires 10 s of keepalives (every 500 ms) to keep getting answered on both sides.

### Stage 3: port prediction, birthday probing, relay

Same 5×5 matrix with the stage 3 techniques on. Success is still the **direct** rate; attempts that fail it fall back to a relay after 3 s (relay usage table below).

- **NAT characterization**: three STUN requests from the agent's one socket (primary, other IP, other port) tell endpoint-independent, sequential symmetric (+ step) and random symmetric mappings apart.
- **Port prediction** (peer behind `symmetric-sequential`): probe the next ports the peer's NAT will hand out. When both sides are sequential, each side's k-th prediction is offset so it leaves from exactly the mapping the other side's k-th prediction targets.
- **Birthday probing** (`symmetric-random` vs a cone NAT): the random side probes from 256 extra sockets, the cone side guesses 256 ports on the peer's IP; expected hit rate 1 − e^(−256·256/64512) ≈ 64%.
- **Relay**: after 3 s the agents bind to the relay the coordination server picked (lowest RTT_A + RTT_B) with a shared token and probe through it.
- **Triggered checks** on every incoming request (also a change to the stage 2 code path).

<!-- report:stage3:start -->
Success rate [Wilson 95% CI], n = 100 attempts per cell.

| NAT A \ NAT B | full | restricted | port-restricted | symmetric-random | symmetric-sequential |
|---|---|---|---|---|---|
| full | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| restricted | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] | 100% [96–100] |
| port-restricted | 100% [96–100] | 100% [96–100] | 100% [96–100] | 63% [53–72] | 100% [96–100] |
| symmetric-random | 100% [96–100] | 100% [96–100] | 63% [53–72] | 0% [0–4] | 0% [0–4] |
| symmetric-sequential | 100% [96–100] | 100% [96–100] | 100% [96–100] | 0% [0–4] | 100% [96–100] |

Time to connect, median / p95 in ms (successful attempts only).

| NAT A \ NAT B | full | restricted | port-restricted | symmetric-random | symmetric-sequential |
|---|---|---|---|---|---|
| full | 45 / 46 | 45 / 45 | 45 / 45 | 26 / 27 | 45 / 46 |
| restricted | 45 / 45 | 45 / 46 | 45 / 46 | 28 / 29 | 45 / 47 |
| port-restricted | 45 / 46 | 45 / 46 | 45 / 45 | 212 / 318 | 68 / 69 |
| symmetric-random | 26 / 30 | 28 / 31 | 191 / 308 | — | — |
| symmetric-sequential | 45 / 46 | 46 / 46 | 68 / 69 | — | 54 / 55 |

Relay usage: attempts that fell back to the relay [Wilson 95% CI].

| NAT A \ NAT B | full | restricted | port-restricted | symmetric-random | symmetric-sequential |
|---|---|---|---|---|---|
| full | 0% [0–4] | 0% [0–4] | 0% [0–4] | 0% [0–4] | 0% [0–4] |
| restricted | 0% [0–4] | 0% [0–4] | 0% [0–4] | 0% [0–4] | 0% [0–4] |
| port-restricted | 0% [0–4] | 0% [0–4] | 0% [0–4] | 37% [28–47] | 0% [0–4] |
| symmetric-random | 0% [0–4] | 0% [0–4] | 37% [28–47] | 100% [96–100] | 100% [96–100] |
| symmetric-sequential | 0% [0–4] | 0% [0–4] | 0% [0–4] | 100% [96–100] | 0% [0–4] |
<!-- report:stage3:end -->

#### Relay → direct upgrade

A connection that started on the relay retries the direct path in the background. In production the retry interval is 30 s; this experiment uses 5 s so it fits in an hour. Only random symmetric vs port-restricted can upgrade at all in the lab (each retry is a fresh 64% birthday draw); the other relayed pairs never get a direct path.

<!-- report:upgrade:start -->
| NAT A × NAT B | started on relay | upgraded to direct | upgrade time, median / p95 ms |
|---|---|---|---|
| port-restricted × symmetric-random | 8 | 100% [68–100] | 5057 / 5256 |
| symmetric-random × port-restricted | 6 | 100% [61–100] | 5192 / 10034 |
<!-- report:upgrade:end -->

### Stage 4: traffic through the tunnel (lab)

Real IP traffic between TUN devices (peerA 10.99.0.1, peerB 10.99.0.2) through WireGuard (BoringTun) over the path the agents found, measured from peerA: 50 pings and a 5 s iperf3 TCP transfer per run. The lab's links have no delay, so ping shows the cost of the tunnel itself. The `symmetric-sequential` pair is limited by the userspace NAT, which copies every packet through user space; that is not WireGuard's limit.

On every relayed run, tcpdump checks the relay hop: the pings carry a marker that is visible on peerA's TUN device and never in the packets to or from the relay. The last relayed capture is kept as `results/stage4_relay_hop.pcap` (not committed: `*.pcap` is git-ignored).

<!-- report:stage4:start -->
| NAT A × NAT B | path | runs | ping, median ms | loss, worst | iperf3, median / min Mbit/s |
|---|---|---|---|---|---|
| port-restricted × port-restricted | direct | 5 | 0.56 | 0% | 813 / 724 |
| symmetric-random × port-restricted | direct | 3 | 0.54 | 0% | 760 / 741 |
| symmetric-random × port-restricted | relay | 2 | 0.71 | 0% | 651 / 651 |
| symmetric-random × symmetric-random | relay | 5 | 0.83 | 0% | 741 / 598 |
| symmetric-sequential × symmetric-sequential | direct | 5 | 0.92 | 0% | 330 / 313 |
<!-- report:stage4:end -->

Real networks (home ↔ OCI, hotspot ↔ OCI, home ↔ hotspot) and NAT mapping lifetimes are not measured yet.

## Build

```sh
cmake -B build -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build
ctest --test-dir build
```

On Ubuntu 24.04 you can skip vcpkg and use the distro packages, then `cmake -B build` without the toolchain file:

```sh
sudo apt install cmake g++ libgtest-dev libssl-dev libsqlite3-dev \
  libgrpc++-dev libprotobuf-dev protobuf-compiler protobuf-compiler-grpc iproute2 iperf3 tcpdump
curl --proto '=https' -sSf https://sh.rustup.rs | sh   # Rust, to build BoringTun (stage 4)
```

Without Rust everything builds except the WireGuard data plane (CMake prints a warning). CI (`.github/workflows/ci.yml`) builds, runs the unit tests and a reduced lab matrix on every push.

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

sudo ./lab/run_stage2.sh stage3             # stage 3 techniques + relay -> results/stage3_improved.csv
sudo ./lab/run_stage2.sh upgrade            # relay -> direct upgrades -> results/stage3_upgrade.csv
sudo ./lab/check_coord_outage.sh symmetric-random symmetric-random   # relayed path survives too
python3 lab/report.py results/stage3_improved.csv --section stage3 --readme README.md
python3 lab/report.py results/stage3_upgrade.csv --upgrade --section upgrade --readme README.md

sudo ./lab/run_stage4.sh                    # traffic through the tunnel -> results/stage4_lab.csv
python3 lab/report.py results/stage4_lab.csv --stage4 --section stage4 --readme README.md

sudo ./lab/ci.sh                            # the CI regression run: 10 attempts per combination
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
5. Success: an authenticated response to one of our requests. Give up after 3 s and fall back to the relay (stage 3).

## Relay (stage 3)

```sh
build/pierce-relay --listen 203.0.113.10:3480 --secret <hex>
build/pierce-coord --listen 203.0.113.10:50051 --relay 203.0.113.10:3480 --relay 203.0.113.11:3480 --relay-secret <hex>
```

The relay forwards packets between the two endpoints that bound with the same token. A token is `session id | expiry | HMAC(secret)`, issued by the coordination server and checked by the relay alone, so a relayed connection keeps working while the coordination server is down until the token expires (600 s by default). Relay control packets start with `0xFE` (BIND, BOUND, PING, PONG); everything else is forwarded unchanged, so the relay only ever sees WireGuard ciphertext and probes.

## Data plane (stage 4)

```sh
build/pierce-wgkey genkey > a.key; build/pierce-wgkey pubkey < a.key > a.pub   # likewise for B
sudo ip tuntap add dev pierce0 mode tun; sudo ip addr add 10.99.0.1/24 dev pierce0
sudo ip link set pierce0 mtu 1420 up
sudo build/pierce-agent --coord ... --stun ... --id A --peer B \
  --tun pierce0 --wg-key "$(cat a.key)" --wg-peer "$(cat b.pub)" --hold 0
```

After connecting, the agent moves packets between the TUN device and BoringTun, and BoringTun's datagrams go out on the socket and path the connection was made on: the main socket, a birthday socket, or the main socket via the relay. On that socket the first byte tells WireGuard (1–4) and probes (0xFF) apart. Peer public keys are exchanged in advance (here as files), never through the coordination server, so a compromised coordinator cannot slip in a fake peer: the WireGuard handshake would fail.

## Documentation

- `lab/README.md` — NAT lab topology, how each NAT type is built, the userspace NAT

# The VPNGate tunnel layer

These are the scripts that put Thai egresses *under* `/opt/netninja/geo-nodes.txt`, the pool file the proxy
hot-reloads. [`../netninja-th-pool.sh`](../netninja-th-pool.sh) is the supervisor that decides what gets
published; this directory is the machinery it drives, plus the legacy slot the proxy's geo guard rotates.

They lived only on the server until now, which meant a rebuilt VM had to be reverse-engineered from its running
config. The copies here are the ones installed there — the md5 of each file matches its destination.

## Where each file goes, and what it does

| Here | Installed as | What it is |
|---|---|---|
| `vpngate-rotate.sh` | `/opt/vpngate/vpngate-rotate.sh` | Failover for the **legacy** Thai tunnel (slot 1). Revives the current config, otherwise picks a fresh VPNGate node that really exits `EXPECT_COUNTRY`. |
| `watch.sh` | `/opt/vpngate/watch.sh` | Watchdog on the legacy tunnel, run by `vpngate-watch.timer` every 30s: bounce once, rotate if still unhealthy. |
| `ovpn-up.sh` | `/opt/vpngate/ovpn-up.sh` | OpenVPN `--up` hook for the legacy tunnel: source address, routing table 310, SOCKS5 listener. |
| `ovpn-down.sh` | `/opt/vpngate/ovpn-down.sh` | `--down` hook for the legacy tunnel. |
| `slot-up.sh` | `/opt/vpngate/slot-up.sh` | `--up` hook for a numbered slot. Derives the slot from the tun device name, so slot *N* owns `172.30.77.(N+1)`, table `309+N` and its own listener. |
| `slot-down.sh` | `/opt/vpngate/slot-down.sh` | `--down` hook for a numbered slot; tears down only that slot. |
| `netninja-th-slot-up.sh` | `/usr/local/sbin/netninja-th-slot-up.sh` | Rebuilds slot *N* from scratch: walks the Thai nodes, skips ones another slot holds or that recently failed, and only reports success once that slot's SOCKS5 really exits TH. Used by the supervisor as `SLOT_<n>_REPLACE`. |
| `vpngate-th@.service` | `/etc/systemd/system/vpngate-th@.service` | Unit template for a numbered slot (own tun, routing table and listener). |
| `install-slots.sh` | — (run once from a checkout) | Installs all of the above, resets the slots it is told to manage, declares them in `/etc/netninja/th-pool.conf` and restarts the supervisor. |

Slot 1 is deliberately **not** in this table's systemd template: it stays the pre-existing `vpngate-th.service`,
and `vpngate-rotate.sh` / `watch.sh` are what keep it Thai. Numbered slots (`vpngate-th@2`, …) are owned by
`install-slots.sh` and the supervisor.

## Install

```bash
scp -r scripts/vpngate <user>@<vm>:/tmp/netninja-slots
ssh <user>@<vm> 'sudo bash /tmp/netninja-slots/install-slots.sh'   # SLOTS="2 3" to add slots
```

`SLOTS` should list only as many slots as there are usable Thai nodes; a slot that cannot exist just burns the
supervisor's rotation budget.

## Invariants worth keeping

Each of these was a real outage on this deployment, and each is why the code looks slightly more careful than a
failover script needs to:

- **Success means "exits `EXPECT_COUNTRY`", not "answers HTTP 200".** A tunnel that drifted to another country
  answers 200 just the same. Crediting that as success is how the legacy slot sat on a Japanese exit while the
  log said `SUCCESS TH`, leaving the Thai pool a node short.
- **Only one rotation at a time** (`flock`), and each run uses its own scratch files. The watchdog fires every
  30s while a rotation takes minutes, and two runs sharing `candidate.ovpn` meant run A logged a Thai success
  and then copied run B's Japanese config into `active.ovpn`.
- **Kill by address, never by binary name.** `pkill -f socks5ns` matched every slot's listener, so each
  failover silently took the *other* slots' SOCKS5 ports down with it — the slot's openvpn stayed up and never
  rebuilt them.
- **Test tunnels must not outlive their attempt.** A leaked `openvpn --config candidate.*` keeps re-running
  `ovpn-up.sh` on every reconnect, rewriting slot 1's address and listener under the real service.
- **A tunnel that works but exits the wrong country is still useful** (`HOP_SOCKS5` points at the legacy
  listener), so the rotate script keeps a reachable foreign config rather than tearing it down, and only Thai
  candidates are remembered as dead.
- **Waiting is a steady state.** When no Thai node is usable, a hunt must finish in seconds and leave the
  working tunnel alone, not spend minutes re-testing nodes that just failed.

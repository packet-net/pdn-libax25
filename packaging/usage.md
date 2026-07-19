# pdn-libax25 — usage

`pdn-libax25` lets **unmodified** Linux AF_AX25 applications (`ax25-apps`,
`ax25-tools`, FBB, …) use the **pdn** AX.25 stack (packet.net) instead of the
Linux kernel `AF_AX25` stack (removed from mainline in Linux 7.1).

## What this package installs

It is **opt-in** and does **not** replace or hijack the system AX.25 library.
Everything lands in the **private** path `/usr/lib/pdn-libax25/`:

| Path | What |
|------|------|
| `/usr/lib/pdn-libax25/libax25.so.1.0.1` | the real helper library |
| `/usr/lib/pdn-libax25/libax25.so.1` | SONAME symlink → `libax25.so.1.0.1` |
| `/usr/lib/pdn-libax25/libax25.so` | dev symlink → `libax25.so.1` |
| `/usr/lib/pdn-libax25/ax25-interpose.so` | the `LD_PRELOAD` libc interposer |
| `/usr/bin/pdn-ax25` | wrapper that turns the shim on for one command |

Because nothing is installed on the default library search path and no
`ldconfig` is run into it, the distro `libax25` (if present) is untouched.

## Running an app through the shim

Use the `pdn-ax25` wrapper — it sets `LD_LIBRARY_PATH` and `LD_PRELOAD` for the
single command you give it:

```sh
# connected-mode call via ax25-apps, unmodified:
PDN_RHP_ADDR=127.0.0.1:9000 pdn-ax25 axcall radio GB7RDG

# a UI beacon, an ax25d listener, etc. — anything AF_AX25:
pdn-ax25 ax25d
```

`PDN_RHP_ADDR` points at the pdn node's RHPv2 endpoint and defaults to
`127.0.0.1:9000`. Optional auth via `PDN_RHP_USER` / `PDN_RHP_PASS` (loopback
needs none).

`/etc/ax25/axports` is parsed as usual (`name callsign speed paclen window
description`); set `AX25_AXPORTS` to point at an alternative file for testing.

## Requirements

A running **pdn node with an `ax25` port up**, reachable over RHPv2. This
package is loosely coupled to the node over the network — it does not depend on
it (`Recommends: packetnet`).

See `README.md` (this directory) for the full design notes and
`samples-README.md` for worked C examples of every AF_AX25 path.

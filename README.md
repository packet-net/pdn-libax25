# pdn-libax25

Let **unmodified** Linux ham-radio applications (`ax25-apps`, `ax25-tools`, FBB,
…) use the **pdn** AX.25 stack (packet.net) instead of the Linux kernel
`AF_AX25` stack, which was removed from mainline in Linux 7.1.

It ships **two** native `.so` artifacts (both Rust `cdylib`s), licence
**LGPL-3.0-or-later**:

| Artifact | Role |
|----------|------|
| **`libax25.so.1`** | Drop-in replacement for ve7fet **libax25**'s *helper* library — address parsing (`ax25_aton*`/`ax25_ntoa`/`ax25_cmp`/`ax25_validate`) and `axports` config parsing. libax25 has **no** connection code; apps link `-lax25` only for these helpers. SONAME is `libax25.so.1` (upstream real file `libax25.so.1.0.1`, pkg 1.2.2). |
| **`ax25-interpose.so`** | An `LD_PRELOAD` libc interposer. It wraps the socket/IO calls, detects `AF_AX25` (family 3) + `SOCK_SEQPACKET` sockets, routes them to a pdn **RHPv2** connection, and passes every other call straight through to real libc via `dlsym(RTLD_NEXT, …)`. Build output is `libax25_interpose.so`. |

Both share an internal **`rhp`** crate — an RHPv2 client over loopback TCP
`127.0.0.1:9000` (override with `PDN_RHP_ADDR`).

## Why two pieces

Upstream libax25 is *only* helpers; the actual connection work is done by apps
talking to the kernel `AF_AX25` socket API. With the kernel stack gone:

1. `libax25.so.1` provides the helper ABI apps link against — crucially with
   **`axports` parsing that does NOT require a kernel `ARPHRD_AX25` netdevice**
   (upstream refuses to list a port without one; we omit that check, so every
   well-formed `axports` line is an active port). This is the critical fix.
2. `ax25-interpose.so` provides the *connections*, transparently, by turning
   `AF_AX25` sockets into pdn RHPv2 sessions.

## The RHPv2 client (`rhp` crate)

* Transport: persistent, multiplexed TCP to `127.0.0.1:9000` (env
  `PDN_RHP_ADDR`). Optional `auth` only when `PDN_RHP_USER`/`PDN_RHP_PASS` are
  set (loopback needs none).
* Framing: 2-byte **big-endian** length prefix + that many bytes of UTF-8 JSON
  (≤ 65535).
* `data` fields are **Latin-1** (one byte ↔ one code point), **not** base64.
  Binary-safe over all 256 byte values (unit-tested).
* Correlation: each request carries a monotonic non-zero `id`; replies echo it.
  Async pushes (`recv`/`accept`/`status`/server `close`) carry a per-connection
  `seqno` and no `id`. A single reader thread demultiplexes them.

Implemented clean-room from the RHPv2 wire spec (`rhp2lib-net/docs/protocol.md`,
PWP-0222 / PWP-0245) and the MIT reference client `RhpV2.Client` (used as a model
only — pdn's GPL/AGPL `Packet.Rhp2` is **not** linked).

## Build

Requires a Rust toolchain (`cargo`).

```sh
cargo build --release
cargo test          # address round-trips, Latin-1 codec, framing, RHP client
```

Artifacts land in `target/release/`:

* `libax25.so`  (SONAME `libax25.so.1`)
* `libax25_interpose.so`

Or use the convenience Makefile, which also creates the versioned symlinks
(`libax25.so`, `libax25.so.1`, `libax25.so.1.0.1`) and an `ax25-interpose.so`
alias:

```sh
make            # build + symlinks in target/release
make install    # install into $(PREFIX)/lib (default /usr/local)
```

## Usage

Point apps at the helper lib and preload the interposer:

```sh
# so the dynamic linker finds our libax25.so.1 ahead of the distro package:
export LD_LIBRARY_PATH=/path/to/target/release:$LD_LIBRARY_PATH

# route AF_AX25 sockets to pdn:
export LD_PRELOAD=/path/to/target/release/libax25_interpose.so

# optional: non-default engine address
export PDN_RHP_ADDR=127.0.0.1:9000

axcall radio GB7RDG        # example: an ax25-apps client, unmodified
```

`/etc/ax25/axports` is parsed as usual (`name callsign speed paclen window
description`); set `AX25_AXPORTS` to point at an alternative file for testing.

## Status

Both directions are implemented and verified end-to-end against an in-process
mock RHP server:

* **Outbound** `socket → bind → connect → write → read → close` maps to RHP
  `open → send → recv → close`. `connect()` now honours that AX.25 connect is
  asynchronous: a **blocking** fd blocks until the `status(Connected)` push (not
  the openReply), while an **O_NONBLOCK** fd returns `EINPROGRESS`, becomes
  writable once the link is up, and exposes the result via
  `getsockopt(SO_ERROR)` — so the standard non-blocking-connect + `select`/`poll`
  idiom works.
* **Inbound** `socket → bind → listen → accept` is wired for `ax25d`: `accept()`
  blocks on a condvar (no busy-wait; `EAGAIN` under O_NONBLOCK), returns a child
  fd carrying the caller's callsign, and `getsockname()` reports the local port
  callsign in `fsa_digipeater[0]`.
* **Receive back-pressure**: inbound bytes are never silently dropped — a
  per-handle buffer plus a flusher thread drains into the socketpair as the app
  reads, without stalling the shared RHP reader thread.

Remaining `TODO(N1)` markers cover non-blocking niceties out of scope here (AX.25
timer socket options captured as no-ops; connect-via-digipeater paths; the
`libax25` `get_call` uid→callsign mapping).

## Licence

LGPL-3.0-or-later. See [`COPYING.LESSER`](COPYING.LESSER) (LGPL-3.0) and
[`COPYING`](COPYING) (GPL-3.0). Address/config logic was reimplemented
clean-room from ve7fet libax25 (GPL) read as a semantic reference only; no GPL
code is copied in. New dependencies (`serde`, `serde_json`, `libc`) are
MIT/Apache-2.0.

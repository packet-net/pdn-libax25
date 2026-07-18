# pdn-libax25 samples

Four tiny, heavily-commented C programs that use the **standard `AF_AX25`
socket API** — the exact same calls (`socket`/`bind`/`connect`/`accept`/
`sendto`/`recvfrom`) that `ax25-apps`, `ax25-tools`, FBB and friends make. They
contain **nothing pdn-specific**. The point of the samples is that *unmodified*
AF_AX25 code just works against a pdn node when you preload the interposer shim:
no source changes, no relinking — the `LD_PRELOAD` shim redirects the AF_AX25
sockets to pdn over RHPv2.

| Sample | Type | What it shows |
|--------|------|---------------|
| `ax25_connect.c` | `SOCK_SEQPACKET` | connected-mode **client** — call a station, send a line, print the reply |
| `ax25_answer.c` | `SOCK_SEQPACKET` | connected-mode **listener** — `bind`/`listen`/`accept`, greet + echo (à la `ax25d`) |
| `ax25_beacon.c` | `SOCK_DGRAM` | UI/datagram **sender** — fire one beacon frame and exit (default PID `0xF0`) |
| `ax25_ui_monitor.c` | `SOCK_DGRAM` | UI/datagram **receiver** — print `src>dest [pid] text` for every UI frame heard |

## Licence

The sample `.c` files are **`0BSD`** (SPDX `0BSD`) — copy, paste and adapt them
freely with no strings attached. Note this is *only* the samples: the interposer
shim itself (`libax25_interpose.so`) and the rest of this repo are
**LGPL-3.0-or-later**.

## Build

No library is linked — the samples use the raw socket API, so plain `cc` is all
you need:

```sh
cc -O2 -o ax25_connect     ax25_connect.c
cc -O2 -o ax25_answer      ax25_answer.c
cc -O2 -o ax25_beacon      ax25_beacon.c
cc -O2 -o ax25_ui_monitor  ax25_ui_monitor.c
```

(Or run `make samples` from the repo root.) They include `<netax25/ax25.h>` for
the `sockaddr_ax25` struct definitions — on Debian/Ubuntu that header comes from
the `libax25-dev` package — but they **do not link `-lax25`**: the shifted-ASCII
callsign encoding that `ax25_aton()` would normally do is inlined in each file so
there is no library dependency at all.

## Run

You need a **pdn node with an `ax25` port up**, reachable over RHPv2 (default
`127.0.0.1:9000`). Then preload the interposer and run the sample as usual:

```sh
LD_PRELOAD=/path/to/target/release/libax25_interpose.so \
PDN_RHP_ADDR=127.0.0.1:9000 \
    ./ax25_connect GB7RDG-1 M0ABC-1        # call GB7RDG-1 as M0ABC-1
```

```sh
LD_PRELOAD=/path/to/target/release/libax25_interpose.so \
PDN_RHP_ADDR=127.0.0.1:9000 \
    ./ax25_beacon M0ABC-1 BEACON "hello from pdn"   # one UI frame, PID 0xF0
```

```sh
LD_PRELOAD=/path/to/target/release/libax25_interpose.so \
    ./ax25_answer GB7RDG-1          # answer inbound connections as GB7RDG-1
LD_PRELOAD=/path/to/target/release/libax25_interpose.so \
    ./ax25_ui_monitor MYMON-1       # print every UI frame heard on the port
```

`PDN_RHP_ADDR` defaults to `127.0.0.1:9000`; set it only for a non-default
engine. These samples do **not** link `-lax25`, so they do **not** read
`/etc/ax25/axports` — you don't need an `axports` entry to run them. (You only
need `axports` when an app links the `libax25.so.1` helper library.)

## When to use which: connected mode vs UI/datagram

**One line: connected mode is a phone call; UI is a postcard.**

**Connected mode — `SOCK_SEQPACKET` (`ax25_connect` / `ax25_answer`).** A
reliable, ordered, acknowledged *session*, much like TCP. AX.25's Layer-2 ARQ
retransmits lost frames, so every byte arrives, once, in order, for the life of
the link. Use it whenever you need a real conversation with one station and can't
afford to lose data: **BBS logins, keyboard-to-keyboard chat, file and mail
transfer, remote-node/sysop sessions.** The cost is a SABM/UA handshake to set up
and a DISC/UA to tear down, and it ties up a circuit to exactly one peer for the
duration.

**UI / datagram — `SOCK_DGRAM` (`ax25_beacon` / `ax25_ui_monitor`).**
Connectionless, unacknowledged, one-shot frames, much like UDP. There is **zero
setup**: you just address a frame and send it, to any destination — including
broadcast-style pseudo-calls — and any station on frequency can hear it
promiscuously. But a UI frame that collides or fades is simply **lost, with no
retry**. Use it for **beacons, APRS position/telemetry, announcements, ID
frames**, and — with `AX25_PIDINCL` and PID `0xCC` — **IP-over-AX.25 datagrams**.

The trade-off in a sentence: **connected mode guarantees delivery but costs a
handshake, a teardown, and a dedicated circuit to one peer; UI has no setup and
reaches everyone at once, but any given frame may vanish without notice.** Reach
for connected mode when *every byte matters to one station*, and UI when you want
to *shout something once to whoever's listening*.

## These are unmodified standard AF_AX25 programs

Nothing in these files knows about pdn, RHPv2, or the shim. They are ordinary
Linux AX.25 socket programs — the same code you'd write against the old kernel
`AF_AX25` stack. The whole point is that they run unchanged against pdn purely
via the `LD_PRELOAD` interposer. Copy any of them into your own project as a
starting point.

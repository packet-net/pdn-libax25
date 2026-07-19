// SPDX-License-Identifier: AGPL-3.0-or-later
//
// libax25 — a drop-in replacement for the ve7fet libax25 *helper* library.
//
// Upstream libax25 has NO connection code: it is purely address parsing
// (axutils.c) and config parsing (axconfig.c) plus tty/daemon/proc helpers.
// Apps link `-lax25` for those helpers and then talk to the kernel AF_AX25
// socket API directly. With the kernel stack gone (Linux 7.1), the connection
// side is provided by `ax25-interpose` (LD_PRELOAD); this library only needs to
// provide the helper ABI — crucially with axports parsing that DOESN'T require
// a kernel netdevice (see config.rs).
//
// SONAME is stamped `libax25.so.1` by build.rs to match upstream's
// libax25.so.1.0.1 (pkg 1.2.2), so `-lax25` linkage resolves to this crate.
//
// Provenance: address/config logic reimplemented clean-room from ve7fet
// libax25 (GPL: lib/ax25/axutils.c, lib/ax25/axconfig.c) READ as a semantic
// reference only, plus the public AX.25 encoding. Per-file notes at the top of
// addr.rs / config.rs / stubs.rs.

#![allow(non_upper_case_globals)] // C ABI data symbols keep their C names.

pub mod addr;
pub mod config;
pub mod stubs;

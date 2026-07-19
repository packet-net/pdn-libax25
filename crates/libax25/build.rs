// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Set the SONAME of the produced cdylib to `libax25.so.1`, matching upstream
// ve7fet libax25 (real file libax25.so.1.0.1, SONAME libax25.so.1, pkg 1.2.2)
// so that binaries linked against the distro package load our replacement.

fn main() {
    // The lib name is `ax25`, so cargo emits `libax25.so`; override its SONAME.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libax25.so.1");
    // Rerun only if this script changes.
    println!("cargo:rerun-if-changed=build.rs");
}

#!/usr/bin/env bash
#
# build-deb.sh — build the two pdn-libax25 cdylibs for one architecture and
# package them as a Debian .deb. Used locally and by .github/workflows/release.yml.
#
#   scripts/build-deb.sh <arch> <version>
#   e.g. scripts/build-deb.sh amd64 0.1.0
#
# amd64 builds native; arm64/armhf cross-compile from x86_64 (the .cargo/config.toml
# linkers + gcc-*-linux-gnu*). Produces artifacts/pdn-libax25_<version>_<arch>.deb.
#
# The package is OPT-IN (CLAUDE.md / task pins): the .so artifacts go to the PRIVATE
# path /usr/lib/pdn-libax25/ — NOT the default library path, NO ldconfig, NO
# Provides/Conflicts on the distro libax25 — so it never hijacks system AX.25.
set -euo pipefail

arch="${1:?usage: build-deb.sh <arch> <version> (arch: amd64|arm64|armhf)}"
version="${2:?usage: build-deb.sh <arch> <version>}"

case "$arch" in
  amd64) triple=x86_64-unknown-linux-gnu ;;
  arm64) triple=aarch64-unknown-linux-gnu ;;
  armhf) triple=arm-unknown-linux-gnueabihf ;;
  *) echo "unknown arch: $arch (want amd64 | arm64 | armhf)" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
reldir="$root/target/$triple/release"
stage="$root/artifacts/deb/$arch"
out="$root/artifacts/pdn-libax25_${version}_${arch}.deb"

echo "==> cargo build --release --target $triple ($arch)"
( cd "$root" && cargo build --release --target "$triple" )

# The two cdylibs cargo emits:
#   libax25.so           — SONAME libax25.so.1 (build.rs), the helper lib
#   libax25_interpose.so — the LD_PRELOAD interposer
src_helper="$reldir/libax25.so"
src_interpose="$reldir/libax25_interpose.so"
[ -f "$src_helper" ]    || { echo "missing $src_helper (cargo build failed?)" >&2; exit 1; }
[ -f "$src_interpose" ] || { echo "missing $src_interpose (cargo build failed?)" >&2; exit 1; }

echo "==> stage .deb tree for $arch"
rm -rf "$stage"
libdir="$stage/usr/lib/pdn-libax25"
docdir="$stage/usr/share/doc/pdn-libax25"
install -d "$stage/DEBIAN" "$libdir" "$stage/usr/bin" "$docdir"

# --- the private-path libraries + conventional symlinks ---
# Real file is libax25.so.1.0.1 (upstream ve7fet real-file name); libax25.so.1 is
# the SONAME symlink apps load; libax25.so is the linker/dev symlink.
install -m 0644 "$src_helper" "$libdir/libax25.so.1.0.1"
ln -sf libax25.so.1.0.1 "$libdir/libax25.so.1"
ln -sf libax25.so.1     "$libdir/libax25.so"
install -m 0644 "$src_interpose" "$libdir/ax25-interpose.so"

# --- the per-command wrapper ---
install -m 0755 "$root/packaging/pdn-ax25" "$stage/usr/bin/pdn-ax25"

# --- docs: usage + the repo/samples READMEs + copyright ---
install -m 0644 "$root/packaging/usage.md"  "$docdir/usage.md"
install -m 0644 "$root/README.md"           "$docdir/README.md"
install -m 0644 "$root/samples/README.md"   "$docdir/samples-README.md"
install -m 0644 "$root/packaging/copyright" "$docdir/copyright"

# --- control ---
sed -e "s/@ARCH@/$arch/" -e "s/@VERSION@/$version/" \
    "$root/packaging/control.in" > "$stage/DEBIAN/control"

echo "==> build .deb"
mkdir -p "$root/artifacts"
# --root-owner-group (dpkg >= 1.19): root:root files without fakeroot.
dpkg-deb --build --root-owner-group "$stage" "$out"

echo "==> built $out"
dpkg-deb --info "$out"
echo "--- contents ---"
dpkg-deb --contents "$out"

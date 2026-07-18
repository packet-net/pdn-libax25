# pdn-libax25 convenience Makefile.
#
# `cargo build` is the source of truth; this just adds the conventional
# versioned symlinks and an install target. Licence: LGPL-3.0-or-later.

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
REL    := target/release

.PHONY: all build symlinks test install clean

all: build symlinks

build:
	cargo build --release

test:
	cargo test

# Create the SONAME / versioned symlinks and the interposer alias.
symlinks: build
	ln -sf libax25.so $(REL)/libax25.so.1
	ln -sf libax25.so $(REL)/libax25.so.1.0.1
	ln -sf libax25_interpose.so $(REL)/ax25-interpose.so
	@echo "symlinks created in $(REL)"

install: all
	install -d $(DESTDIR)$(LIBDIR)
	install -m 0755 $(REL)/libax25.so $(DESTDIR)$(LIBDIR)/libax25.so.1.0.1
	ln -sf libax25.so.1.0.1 $(DESTDIR)$(LIBDIR)/libax25.so.1
	ln -sf libax25.so.1     $(DESTDIR)$(LIBDIR)/libax25.so
	install -m 0755 $(REL)/libax25_interpose.so $(DESTDIR)$(LIBDIR)/ax25-interpose.so
	@echo "installed to $(DESTDIR)$(LIBDIR)"

clean:
	cargo clean

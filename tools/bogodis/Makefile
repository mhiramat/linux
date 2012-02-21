AWK := LC_ALL=C awk

# Architecture identifying: copied from tools/perf/Makefile
uname_M := $(shell uname -m 2>/dev/null || echo not)

ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ \
				  -e s/arm.*/arm/ -e s/sa110/arm/ \
				  -e s/s390x/s390/ -e s/parisc64/parisc/ \
				  -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
				  -e s/sh[234].*/sh/ )

# Additional ARCH settings for x86
ifeq ($(ARCH),i386)
        ARCH := x86
endif
ifeq ($(ARCH),x86_64)
	ARCH := x86
endif

ifneq ($(ARCH),x86)
	$(echo "This architecture is not supported yet.")
endif

topdir := ../..
archdir := $(topdir)/arch/$(ARCH)
tooldir := $(archdir)/tools
libdir := $(archdir)/lib
incdir := $(archdir)/include/asm

CFLAGS := -g -Wall -I$(topdir)/include -I$(archdir)/include

SRC += $(libdir)/insn.c
SRC += $(libdir)/inat.c
SRC += $(libdir)/disasm.c
SRC += $(libdir)/mnemonic.c
SRC += $(incdir)/inat_types.h
SRC += $(incdir)/inat.h
SRC += $(incdir)/insn.h
SRC += $(incdir)/disasm.h

bogodis: bogodis.c inat-tables.c mnemonic-tables.c $(SRC)
	$(CC) $(CFLAGS) -o $@ bogodis.c -I$(libdir) -I./

inat-tables.c: $(libdir)/x86-opcode-map.txt $(tooldir)/gen-insn-attr-x86.awk
	$(AWK) -f $(tooldir)/gen-insn-attr-x86.awk $< > $@

mnemonic-tables.c: $(libdir)/x86-opcode-map.txt $(tooldir)/gen-insn-mnemonic-x86.awk
	$(AWK) -f $(tooldir)/gen-insn-mnemonic-x86.awk $< > $@

clean:
	rm -f bogodis *.o inat-tables.c mnemonic-tables.c

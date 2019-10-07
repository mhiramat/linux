# SPDX-License-Identifier: GPL-2.0
_TARGETS = android
_TARGETS += bpf
_TARGETS += breakpoints
_TARGETS += capabilities
_TARGETS += cgroup
_TARGETS += cpufreq
_TARGETS += cpu-hotplug
_TARGETS += drivers/dma-buf
_TARGETS += efivarfs
_TARGETS += exec
_TARGETS += filesystems
_TARGETS += filesystems/binderfs
_TARGETS += firmware
_TARGETS += ftrace
_TARGETS += futex
_TARGETS += gpio
_TARGETS += intel_pstate
_TARGETS += ipc
_TARGETS += ir
_TARGETS += kcmp
_TARGETS += kexec
_TARGETS += kvm
_TARGETS += lib
_TARGETS += livepatch
_TARGETS += membarrier
_TARGETS += memfd
_TARGETS += memory-hotplug
_TARGETS += mount
_TARGETS += mqueue
_TARGETS += net
_TARGETS += netfilter
_TARGETS += networking/timestamping
_TARGETS += nsfs
_TARGETS += pidfd
_TARGETS += powerpc
_TARGETS += proc
_TARGETS += pstore
_TARGETS += ptrace
_TARGETS += rseq
_TARGETS += rtc
_TARGETS += seccomp
_TARGETS += sigaltstack
_TARGETS += size
_TARGETS += sparc64
_TARGETS += splice
_TARGETS += static_keys
_TARGETS += sync
_TARGETS += sysctl
ifneq (1, $(quicktest))
_TARGETS += timers
endif
_TARGETS += tmpfs
_TARGETS += tpm2
_TARGETS += user
_TARGETS += vm
_TARGETS += x86
_TARGETS += zram
#Please keep the _TARGETS list alphabetically sorted
# Run "make quicktest=1 run_tests" or
# "make quicktest=1 kselftest" from top level Makefile

TARGETS ?= $(_TARGETS)

TARGETS_HOTPLUG = cpu-hotplug
TARGETS_HOTPLUG += memory-hotplug

# Clear LDFLAGS and MAKEFLAGS if called from main
# Makefile to avoid test build failures when test
# Makefile doesn't have explicit build rules.
ifeq (1,$(MAKELEVEL))
override LDFLAGS =
override MAKEFLAGS =
endif

# Append kselftest to KBUILD_OUTPUT to avoid cluttering
# KBUILD_OUTPUT with selftest objects and headers installed
# by selftests Makefile or lib.mk.
ifdef building_out_of_srctree
override LDFLAGS =
endif

ifneq ($(O),)
	BUILD := $(O)
else
	ifneq ($(KBUILD_OUTPUT),)
		BUILD := $(KBUILD_OUTPUT)/kselftest
	else
		BUILD := $(shell pwd)
		DEFAULT_INSTALL_HDR_PATH := 1
	endif
endif

# Prepare for headers install
top_srcdir ?= ../../..
include $(top_srcdir)/scripts/subarch.include
ARCH           ?= $(SUBARCH)
export KSFT_KHDR_INSTALL_DONE := 1
export BUILD

# build and run gpio when output directory is the src dir.
# gpio has dependency on tools/gpio and builds tools/gpio
# objects in the src directory in all cases making the src
# repo dirty even when objects are relocated.
ifneq (1,$(DEFAULT_INSTALL_HDR_PATH))
	TMP := $(filter-out gpio, $(TARGETS))
	TARGETS := $(TMP)
endif

# set default goal to all, so make without a target runs all, even when
# all isn't the first target in the file.
.DEFAULT_GOAL := all

# Install headers here once for all tests. KSFT_KHDR_INSTALL_DONE
# is used to avoid running headers_install from lib.mk.
# Invoke headers install with --no-builtin-rules to avoid circular
# dependency in "make kselftest" case. In this case, second level
# make inherits builtin-rules which will use the rule generate
# Makefile.o and runs into
# "Circular Makefile.o <- prepare dependency dropped."
# and headers_install fails and test compile fails.
#
# O= KBUILD_OUTPUT cases don't run into this error, since main Makefile
# invokes them as sub-makes and --no-builtin-rules is not necessary,
# but doesn't cause any failures. Keep it simple and use the same
# flags in both cases.
# Local build cases: "make kselftest", "make -C" - headers are installed
# in the default INSTALL_HDR_PATH usr/include.
khdr:
ifeq (1,$(DEFAULT_INSTALL_HDR_PATH))
	$(MAKE) --no-builtin-rules ARCH=$(ARCH) -C $(top_srcdir) headers_install
else
	$(MAKE) --no-builtin-rules INSTALL_HDR_PATH=$$BUILD/usr \
		ARCH=$(ARCH) -C $(top_srcdir) headers_install
endif

all: khdr
	@for TARGET in $(TARGETS); do		\
		BUILD_TARGET=$$BUILD/$$TARGET;	\
		mkdir $$BUILD_TARGET  -p;	\
		$(MAKE) OUTPUT=$$BUILD_TARGET -C $$TARGET;\
	done;

run_tests: all
	@for TARGET in $(TARGETS); do \
		BUILD_TARGET=$$BUILD/$$TARGET;	\
		$(MAKE) OUTPUT=$$BUILD_TARGET -C $$TARGET run_tests;\
	done;

hotplug:
	@for TARGET in $(TARGETS_HOTPLUG); do \
		BUILD_TARGET=$$BUILD/$$TARGET;	\
		$(MAKE) OUTPUT=$$BUILD_TARGET -C $$TARGET;\
	done;

run_hotplug: hotplug
	@for TARGET in $(TARGETS_HOTPLUG); do \
		BUILD_TARGET=$$BUILD/$$TARGET;	\
		$(MAKE) OUTPUT=$$BUILD_TARGET -C $$TARGET run_full_test;\
	done;

clean_hotplug:
	@for TARGET in $(TARGETS_HOTPLUG); do \
		BUILD_TARGET=$$BUILD/$$TARGET;	\
		$(MAKE) OUTPUT=$$BUILD_TARGET -C $$TARGET clean;\
	done;

run_pstore_crash:
	$(MAKE) -C pstore run_crash

# Use $BUILD as the default install root. $BUILD points to the
# right output location for the following cases:
# 1. output_dir=kernel_src
# 2. a separate output directory is specified using O= KBUILD_OUTPUT
# 3. a separate output directory is specified using KBUILD_OUTPUT
#
INSTALL_PATH ?= $(BUILD)/install
INSTALL_PATH := $(abspath $(INSTALL_PATH))
ALL_SCRIPT := $(INSTALL_PATH)/run_kselftest.sh

install: all
ifdef INSTALL_PATH
	@# Ask all targets to install their files
	mkdir -p $(INSTALL_PATH)/kselftest
	install -m 744 kselftest/runner.sh $(INSTALL_PATH)/kselftest/
	install -m 744 kselftest/prefix.pl $(INSTALL_PATH)/kselftest/
	@for TARGET in $(TARGETS); do \
		BUILD_TARGET=$$BUILD/$$TARGET;	\
		$(MAKE) OUTPUT=$$BUILD_TARGET -C $$TARGET INSTALL_PATH=$(INSTALL_PATH)/$$TARGET install; \
	done;

	@# Ask all targets to emit their test scripts
	echo "#!/bin/sh" > $(ALL_SCRIPT)
	echo "BASE_DIR=\$$(realpath \$$(dirname \$$0))" >> $(ALL_SCRIPT)
	echo "cd \$$BASE_DIR" >> $(ALL_SCRIPT)
	echo ". ./kselftest/runner.sh" >> $(ALL_SCRIPT)
	echo "ROOT=\$$PWD" >> $(ALL_SCRIPT)
	echo "if [ \"\$$1\" = \"--summary\" ]; then" >> $(ALL_SCRIPT)
	echo "  logfile=\$$BASE_DIR/output.log" >> $(ALL_SCRIPT)
	echo "  cat /dev/null > \$$logfile" >> $(ALL_SCRIPT)
	echo "fi" >> $(ALL_SCRIPT)

	for TARGET in $(TARGETS); do \
		BUILD_TARGET=$$BUILD/$$TARGET;	\
		echo "[ -w /dev/kmsg ] && echo \"kselftest: Running tests in $$TARGET\" >> /dev/kmsg" >> $(ALL_SCRIPT); \
		echo "cd $$TARGET" >> $(ALL_SCRIPT); \
		echo -n "run_many" >> $(ALL_SCRIPT); \
		$(MAKE) -s --no-print-directory OUTPUT=$$BUILD_TARGET -C $$TARGET emit_tests >> $(ALL_SCRIPT); \
		echo "" >> $(ALL_SCRIPT);	    \
		echo "cd \$$ROOT" >> $(ALL_SCRIPT); \
	done;

	chmod u+x $(ALL_SCRIPT)
else
	$(error Error: set INSTALL_PATH to use install)
endif

clean:
	@for TARGET in $(TARGETS); do \
		BUILD_TARGET=$$BUILD/$$TARGET;	\
		$(MAKE) OUTPUT=$$BUILD_TARGET -C $$TARGET clean;\
	done;

.PHONY: khdr all run_tests hotplug run_hotplug clean_hotplug run_pstore_crash install clean

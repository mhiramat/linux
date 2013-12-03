CC = gcc

all: trace_filter_check filter_ex1.bpf filter_ex2.bpf

srctree=../../..
src-perf=../../perf

CFLAGS += -I$(src-perf)/util/include
CFLAGS += -I$(src-perf)/arch/$(ARCH)/include
CFLAGS += -I$(srctree)/arch/$(ARCH)/include/uapi
CFLAGS += -I$(srctree)/arch/$(ARCH)/include
CFLAGS += -I$(srctree)/include/uapi
CFLAGS += -I$(srctree)/include
CFLAGS += -Wall -O2

trace_filter_check: LDLIBS = -Wl,--unresolved-symbols=ignore-all
trace_filter_check: trace_filter_check.o \
	$(srctree)/kernel/bpf_jit/bpf_check.o \
	$(srctree)/kernel/bpf_jit/bpf_run.o \
	$(srctree)/kernel/trace/bpf_trace_callbacks.o

filter_ex1: filter_ex1.o
filter_ex1.bpf: filter_ex1
	./filter_ex1 > filter_ex1.bpf
	rm filter_ex1

filter_ex2: filter_ex2.o
filter_ex2.bpf: filter_ex2
	./filter_ex2 > filter_ex2.bpf
	rm filter_ex2

clean:
	rm -rf *.o *.bpf trace_filter_check filter_ex1 filter_ex2


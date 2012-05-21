#!/bin/sh
BUILDDIR=../../
if [ ! -f vmlinux.dis ]; then
objdump -d -M intel $BUILDDIR/vmlinux | awk -f distill.awk > input.dis
fi
./bogodis -i -l 15 < input.dis > output.dis
diff -Eb input.dis output.dis > result.dis

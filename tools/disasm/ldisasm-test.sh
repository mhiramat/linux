#!/bin/sh
DISASM=./ldisasm
WORKDIR=/dev/shm/disasm
[ -d $WORKDIR ] || mkdir -p $WORKDIR

[ -z "$ARCH" ] && ARCH=`uname -m`
VMDIS=$WORKDIR/vmlinux-$ARCH.dis
INDIS=$WORKDIR/input-$ARCH.dis
OUTDIS=$WORKDIR/output-$ARCH.dis

OPT=-6
[ $ARCH = "i386" ] && OPT=-3
[ -z "$BUILDDIR" ] && BUILDDIR=../../

if [ ! -f $VMDIS ]; then
	objdump -d -M intel $BUILDDIR/vmlinux > $VMDIS
fi
cat $VMDIS | awk -f cleansing.awk > $INDIS
$DISASM -i -l 15 $OPT < $INDIS > $OUTDIS
INSNS=`cat $INDIS | wc -l`
diff -Eb $INDIS $OUTDIS > result.diff
DIFFS=`grep "^>" result.diff | wc -l`

echo "Disassemble $INSNS instructions in vmlinux"
echo "and find $DIFFS unknown differences"


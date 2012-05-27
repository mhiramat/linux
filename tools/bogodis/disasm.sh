#!/bin/sh

C=
OPT=
ARCH=

TMP=`mktemp`
CNT=0

gen_obj () {
echo "unsigned char data$CNT[16] = {"
for i in $* ; do
	echo -n 0x$i, 
done
echo "};"
CNT=$((CNT+1))
}

while [ "$1" ]; do
case $1 in
--att|-a)
	OPT=att
	;;
--intel|-i)
	OPT=intel
	;;
--64|-6)
	ARCH=x86-64
	;;
--32|-3)
	ARCH=i386
	;;
*)
	break;
esac
shift 1
done
[ "$OPT" -a "$ARCH" ] && C=","
[ "$OPT" -o "$ARCH" ] && OPT="-M $OPT$C$ARCH"

gen_obj $* | gcc -x c -c - -o $TMP
objdump -j .data $OPT -D $TMP | grep "^ *0:"
rm $TMP

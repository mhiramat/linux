#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only

echo "Boot config test script"

BOOTCONF=./bootconfig
INITRD=`mktemp initrd-XXXX`
TEMPCONF=`mktemp temp-XXXX.bconf`
NG=0

cleanup() {
  rm -f $INITRD $TEMPCONF
  exit $NG
}

trap cleanup EXIT TERM

NO=1

xpass() { # pass test command
  echo "test case $NO ($3)... "
  if ! ($@ && echo "\t\t[OK]"); then
     echo "\t\t[NG]"; NG=$((NG + 1))
  fi
  NO=$((NO + 1))
}

xfail() { # fail test command
  echo "test case $NO ($3)... "
  if ! (! $@ && echo "\t\t[OK]"); then
     echo "\t\t[NG]"; NG=$((NG + 1))
  fi
  NO=$((NO + 1))
}

echo "Basic command test"
xpass $BOOTCONF $INITRD

echo "Delete command should success without bootconfig"
xpass $BOOTCONF -d $INITRD

echo "Max node number check"

echo -n > $TEMPCONF
for i in `seq 1 1024` ; do
   echo "node$i" >> $TEMPCONF
done
xpass $BOOTCONF -a $TEMPCONF $INITRD

echo "badnode" >> $TEMPCONF
xfail $BOOTCONF -a $TEMPCONF $INITRD

echo "Max filesize check"

# Max size is 32767 (including terminal byte)
echo -n "data = \"" > $TEMPCONF
dd if=/dev/urandom bs=768 count=32 | base64 -w0 >> $TEMPCONF
echo "\"" >> $TEMPCONF
xfail $BOOTCONF -a $TEMPCONF $INITRD

truncate -s 32764 $TEMPCONF
echo "\"" >> $TEMPCONF	# add 2 bytes + terminal ('\"\n\0')
xpass $BOOTCONF -a $TEMPCONF $INITRD

echo "=== expected failure cases ==="
for i in samples/bad-* ; do
  xfail $BOOTCONF -a $i $INITRD
done

echo "=== expected success cases ==="
for i in samples/good-* ; do
  xpass $BOOTCONF -a $i $INITRD
done

echo
if [ $NG -eq 0 ]; then
	echo "All tests passed"
else
	echo "$NG tests failed"
fi

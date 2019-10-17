#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0
# gen_kselftest_tar
# Generate kselftest tarball
# Author: Shuah Khan <shuahkh@osg.samsung.com>
# Copyright (C) 2015 Samsung Electronics Co., Ltd.

# main
main()
{
	if [ "$#" -eq 0 ]; then
		echo "$0: Generating default compression gzip"
		copts="cvzf"
		ext=".tar.gz"
	else
		case "$1" in
			tar)
				copts="cvf"
				ext=".tar"
				;;
			targz)
				copts="cvzf"
				ext=".tar.gz"
				;;
			tarbz2)
				copts="cvjf"
				ext=".tar.bz2"
				;;
			tarxz)
				copts="cvJf"
				ext=".tar.xz"
				;;
			*)
			echo "Unknown tarball format $1"
			exit 1
			;;
		esac
		shift 1
	fi

	tmpdir=`mktemp -d ./install-XXXXXX` || exit 1

# Run install using INSTALL_KSFT_PATH override to generate install
# directory
./kselftest_install.sh $tmpdir $@

echo "Finding linked libraries"
(cd $tmpdir
find kselftest/ -type f | while read x ; do
  ldd $x | cut -d'(' -f 1 | grep -v dynamic | cut -d '>' -f 2 ;
done | sort | uniq | xargs tar -ch | tar -x )

tar $copts kselftest${ext} -C $tmpdir kselftest lib
echo "Kselftest archive kselftest${ext} created!"

# clean up install directory
rm -rf $tmpdir
}

main "$@"

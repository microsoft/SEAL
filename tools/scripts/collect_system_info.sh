#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

CMAKE_CXX_COMPILER=cxx_compiler.out
CMAKE_ENV=cmake_env.out
CMAKE_SYSTEM_INFO=system_information.out
SEALDIR=../native/src

CMAKE_CXX_COMPILER_CMD=`cmake -LA $SEALDIR|sed -n 's/^CMAKE_CXX_COMPILER:FILEPATH=\(.*\)$/\1/p'`

echo "Extracting: cmake -LA $SEALDIR > $CMAKE_ENV"
cmake -LA $SEALDIR > $CMAKE_ENV
echo "Extracting: cmake --system-information > $CMAKE_SYSTEM_INFO"
cmake --system-information > $CMAKE_SYSTEM_INFO
echo "Extracting: $CMAKE_CXX_COMPILER_CMD -v > $CMAKE_CXX_COMPILER 2>&1" 
$CMAKE_CXX_COMPILER_CMD -v 2> $CMAKE_CXX_COMPILER

ARCHIVE_NAME=../system_info.tar
FILES=(
	"$SEALDIR/seal/util/config.h"
	"$SEALDIR/CMakeCache.txt"
	"$SEALDIR/CMakeFiles/CMakeOutput.log"
	"$SEALDIR/CMakeFiles/CMakeError.log"
	"/proc/cpuinfo"
	"$CMAKE_ENV"
	"$CMAKE_SYSTEM_INFO"
    "$CMAKE_CXX_COMPILER"
)

print_collecting_filename() {
	echo -e "\033[0mCollecting \033[1;32m$1\033[0m"
}

print_skipping_filename() {
	echo -e "\033[0mSkipping \033[1;31m$1\033[0m"
}

add_to_archive() {
	BASENAME=`basename $1`
	cp -f $1 $BASENAME 2>/dev/null
	if [ -s $ARCHIVE_NAME ]
	then
		tar -rf $ARCHIVE_NAME ./$BASENAME
	else
		tar -cf $ARCHIVE_NAME ./$BASENAME
	fi
	rm -f ./$BASENAME
}

rm -f "$ARCHIVE_NAME.gz"

for i in ${FILES[@]}
do
	if [ -r $i ]
	then
		print_collecting_filename $i
		add_to_archive $i
	else
		print_skipping_filename $i
	fi
done

gzip $ARCHIVE_NAME
if [ $? -eq 0 ]
then
	echo "Created `realpath $ARCHIVE_NAME.gz`"
else
	echo "Could not create `realpath $ARCHIVE_NAME.gz`"
	rm -f $ARCHIVE_NAME.gz
fi

echo -n "Cleaning up ... "
rm -f $CMAKE_ENV
rm -f $CMAKE_SYSTEM_INFO
rm -f $CMAKE_CXX_COMPILER
echo done.

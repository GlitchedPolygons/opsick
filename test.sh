#!/bin/sh
REPO=$(dirname "$0")
rm -rf $REPO/build/
mkdir $REPO/build && cd $REPO/build
cmake -DBUILD_SHARED_LIBS=Off -DOPSICK_ENABLE_TESTS=On -DENABLE_COVERAGE=On .. && make
./run_tests
cd $REPO

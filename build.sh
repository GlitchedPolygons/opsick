#!/bin/bash
#
#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

if [ "$(whoami)" = "root" ]; then
  echo "  Please don't run as root/using sudo..."
  exit
fi

PREVCC="$CC"
PREVCXX="$CXX"

if command -v clang &> /dev/null
then
    echo "-- Clang found on system, great! Long live LLVM! :D"
    export CC=clang
    export CXX=clang++
fi

REPO=$(dirname "$0")
rm -rf "$REPO"/out
rm -rf "$REPO"/build
mkdir -p "$REPO"/build && cd "$REPO"/build || exit

cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DCMAKE_BUILD_TYPE=Release .. || exit
cmake --build . --config Release || exit

tar -czvf opsick.tar.gz opsick

export CC="$PREVCC"
export CXX="$PREVCXX"

cd "$REPO" || exit
echo "  Done. Exported build into $REPO/build"
echo "  Check out the opsick.tar.gz file in there! "

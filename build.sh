#!/bin/sh

if [ "$EUID" -e 0 ]
  then echo "  Please don't run as root/using sudo..."
  exit
fi

REPO=$(dirname "$0")
rm -rf "$REPO"/out
rm -rf "$REPO"/build
mkdir -p "$REPO"/build && cd "$REPO"/build || exit
cmake -DBUILD_SHARED_LIBS=Off -DUSE_SHARED_MBEDTLS_LIBRARY=Off -DCMAKE_BUILD_TYPE=Release ..
make
tar -czvf opsick.tar.gz opsick config.toml
cd "$REPO" || exit
echo "  Done. Exported build into $REPO/build"
echo "  Check out the opsick.tar.gz file in there! "

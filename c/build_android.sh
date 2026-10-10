#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"
pkg install -y clang make 2>/dev/null || true
make clean && make
echo "done, binaries in ../bin/"

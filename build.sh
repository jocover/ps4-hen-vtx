#!/bin/bash

set -e

pushd tool
make
popd

pushd kpayload
make
popd

pushd installer
make
popd

rm -f samu_dump.bin
cp installer/installer.bin samu_dump.bin

#tool/bin2js ps4-hen-vtx.bin > payload.js

#sed "s/###/$(cat payload.js)/" exploit.template > exploit/index.html

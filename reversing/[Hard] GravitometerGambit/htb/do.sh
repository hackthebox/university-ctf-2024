#!/bin/bash

set -ex
arm-linux-gnueabihf-objdump -Mforce-thumb -S ${1:-../chal} > enc
python patch.py BINARY=${1:-../chal}
arm-linux-gnueabihf-objdump -Mforce-thumb -S chal_patched > notenc && python diff.py

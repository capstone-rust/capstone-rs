#!/bin/sh
#
# Update the bundled capstone library

# Modify value to update capstone
CAPSTONE_REVISION="8308ace3a0393d9742515019d11ba4254b1d3951"

set -eu

CAPSTONE_DIR=capstone
TEMP_DIR="$(mktemp -d)/$CAPSTONE_DIR"

git clone "https://github.com/aquynh/capstone" "$TEMP_DIR"

rsync \
    -a --exclude='.git' --delete \
    "$TEMP_DIR" "$(dirname "$0")"/../

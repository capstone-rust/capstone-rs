#!/bin/sh
#
# Lists capstone types from capstone includes (enums and structs)

set -eu

SCRIPT_DIR="$(dirname "$0")"
CAPSTONE_INCLUDE="$SCRIPT_DIR/../capstone/include"

grep -Ehro 'typedef (enum|struct) \S+' "$CAPSTONE_INCLUDE" \
    | sed 's/\S\+ \S\+ \(\S\+\)/\1/' \
    | sort -u

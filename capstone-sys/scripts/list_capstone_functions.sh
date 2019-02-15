#!/bin/sh
#
# Lists capstone types from capstone includes (enums and structs)

set -eu

SCRIPT_DIR="$(dirname "$0")"
CAPSTONE_INCLUDE="$SCRIPT_DIR/../capstone/include"

grep -A1 '^CAPSTONE_EXPORT' "$CAPSTONE_INCLUDE"/capstone.h \
    | grep -oE '[^( ]+\(' \
    | tr -d '('

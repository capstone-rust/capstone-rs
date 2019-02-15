#!/bin/sh

usage() {
    cat <<EOF
Usage: $0 CAPSTONE_INCLUDE_PATH

Generates Rust syntax for a list of tuples mapping arch names to a list of enums
EOF
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

INCLUDE_PATH="$1"
cd "$INCLUDE_PATH"

quote_str() {
    while IFS='\n' read -r line; do
        echo "\"$line\""
    done
}

find . -type f -name '*.h' \
        -and -not \( -name 'platform.h' -or -name 'capstone.h' \) | \
        xargs -n1 basename | sort -d | \
while IFS='\n' read -r header; do
    arch_name="$(grep -oE 'struct cs_[^_ ]* ' "$header" | awk '{print $2}' | sed 's/^cs_\([a-z0-9]\+\)$/\1/')"
    enums="$(grep -Eo 'enum [A-Za-z0-9_]+' "$header" | awk '{ print $2 }' | sed -e 's/^/"/' -e 's/$/", /' | tr -d '\n')"
    echo "(\"$arch_name\", &[${enums%%, }]),"
done

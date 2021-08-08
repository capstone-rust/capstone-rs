#!/usr/bin/env bash
# Copy code snippet from src/lib.rs and paste into README.md code sample

set -euo pipefail

cd "$(dirname $0)/.."

# Replace items between markers (including markers) with stdin
# Set REPLACE_MARKERS=1 to OVERWRITE the marker lines
marker_patch() {
    local input="$1"; shift
    local start_marker="$1"; shift
    local end_marker="$1"; shift

    local line_num_pat='s/^\([^:]*\):.*$/\1/g'

    BEGIN_GEN="$(cat "$input" | grep -n "$start_marker" | sed "$line_num_pat")"
    END_GEN="$(cat "$input" | grep -n "$end_marker" | sed "$line_num_pat")"
    head_num=$(expr "$BEGIN_GEN" - 1)
    tail_num=$(expr "$END_GEN" + 1)

    if [ "${REPLACE_MARKERS:+Z}" != "Z" ]; then
        head_num=$(expr "$head_num" + 1)
        tail_num=$(expr "$tail_num" - 1)
    fi

    tmp_file="$(mktemp /tmp/marker-patch-XXXXXX)"

    cat \
        <(head -n "$head_num" "$input") \
        - \
        <(tail -n +"$tail_num" "$input") \
        > "$tmp_file"

    mv "$tmp_file" "$input"
}

cat capstone-rs/src/lib.rs | sed -n '/```rust/,/```/p' | sed -E 's,^//! ?,,' \
    | marker_patch README.md "<!-- START: code_sample -->" "<!-- END: code_sample -->"

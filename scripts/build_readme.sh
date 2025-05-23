#!/bin/sh
#
# Builds README.md as html with GitHub style
# tested with comrak 0.19.0

set -eux

cd "$(dirname "$0")"/..

build() {
    INPUT_MD="$1"
    OUTPUT_HTML="$(echo "${INPUT_MD}" | sed 's,\.md,.html,')"

    if [ ! -f "$INPUT_MD" ]; then
        echo "No '$INPUT_MD', skipping"
        return
    fi

    comrak \
        --gfm \
        "$INPUT_MD" -o "$OUTPUT_HTML"
}

for md in \
    *.md \
    capstone-rs/*.md \
    capstone-sys/*.md \
    cstool/*.md \
    scripts/*.md \
; do
    build "${md}"
done

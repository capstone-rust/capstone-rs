#!/bin/sh
#
# Builds README.md as html with GitHub style
# tested with pandoc 2.1.1

set -eux

cd "$(dirname "$0")"/..

build() {
    dir="$1"; shift
    base="$1"; shift

    INPUT_MD="${dir}/${base}.md"
    OUTPUT_HTML="${dir}/${base}.html"

    if [ ! -f "$INPUT_MD" ]; then
        echo "No '$INPUT_MD', skipping"
        return
    fi

    pandoc \
        -f gfm -t html5 \
        --css scripts/github-md.css -Vpagetitle="${dir}" \
        --standalone \
        "$INPUT_MD" -o "$OUTPUT_HTML"
}

for dir in . capstone-rs capstone-sys cstool; do
    build $dir README
    build $dir CHANGELOG
done

#!/bin/sh
#
# Builds README.md as html with GitHub style
# tested with pandoc 2.1.1

set -eux

cd "$(dirname "$0")"/..

build() {
    dir="$1"; shift
    base="$1"; shift

    pandoc \
        -f gfm -t html5 \
        --css scripts/github-md.css -Vpagetitle="${dir}" \
        --standalone \
        "${dir}/${base}.md" -o "${dir}/${base}.html"
}

for dir in capstone-rs capstone-sys; do
    build $dir README
    build $dir CHANGELOG
done

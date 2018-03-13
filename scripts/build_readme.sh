#!/bin/sh
#
# Builds README.md as html with GitHub style
# tested with pandoc 2.1.1

set -eux

cd "$(dirname "$0")"

build() {
    base="$1"
    pandoc \
        -f gfm -t html5 \
        --css github-md.css -Vpagetitle=capstone-sys \
        --standalone --self-contained \
        ${base}.md -o ${base}.html
}

build ../README
build ../CHANGELOG

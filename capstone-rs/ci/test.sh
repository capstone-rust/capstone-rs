#!/usr/bin/env bash
#
# Modified `ci/test.sh` from capstone-sys
# Environment variables:
#
# FEATURES: (none by default)
# JOB: {*test,valgrind-test,bench,cov}
# PROFILES: list of {debug,release} [debug]
# SHOULD_FAIL: (disabled by default; set to non-empty string to enable)
# VALGRIND_TESTS: run tests under Valgrind

set -euo pipefail

if [ $(basename "$0") = "test.sh" ]; then
    cd "$(dirname "$0")/.."
else
    echo "Script is sourced"
fi

RUST_BACKTRACE=1
SHOULD_FAIL=${SHOULD_FAIL:-}  # Default to false
VALGRIND_TESTS=${VALGRIND_TESTS:-}
FEATURES="${FEATURES-}"  # Default to no features
PROJECT_NAME="$(grep ^name Cargo.toml | head -n1 | xargs -n1 | tail -n1)"
TARGET="../target"
TARGET_COV="${TARGET}/cov"

PASS="PASS"
FAIL="FAIL"

if [ "$SHOULD_FAIL" ]; then
    EXPECTED_RESULT="$FAIL"
else
    EXPECTED_RESULT="$PASS"
fi

echo "Test should $EXPECTED_RESULT"

Error() {
    echo "Error:" "$@" >&2
    exit 1
}

if ! [ "${OS_NAME:-}" ]; then
    case "$(uname)" in
    Linux) OS_NAME=linux ;;
    Darwin) OS_NAME=osx ;;
    FreeBSD) OS_NAME=freebsd ;;
    esac
fi

# Usage: SHOULD_FAIL [ARG1 [ARG2 [...]]]
expect_exit_status() {
    local SHOULD_FAIL="$1"
    shift

    echo "Running command: $*"

    if "$@"; then
        ACTUAL_RESULT="$PASS"
    else
        ACTUAL_RESULT="$FAIL"
    fi

    if [ "$EXPECTED_RESULT" = "$ACTUAL_RESULT" ]; then
        echo "Correctly got expected result $EXPECTED_RESULT"
    else
        Error "Got result $ACTUAL_RESULT, expected result $EXPECTED_RESULT"
    fi
}

install_kcov() {
    if [ -f ./kcov-install/usr/local/bin/kcov ]; then
        echo "kcov already installed"
        return
    fi

    (
        wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
        tar xzf master.tar.gz
        cd kcov-master
        rm -rf build
        mkdir build
        cd build
        cmake ..
        make -j
        make install DESTDIR=../../kcov-install
    )
}

install_valgrind() {
    case "${OS_NAME}" in
    linux)
        sudo apt-get install valgrind -y
        ;;
    osx)
        sudo brew install valgrind
        ;;
    *) Error "Valgrind not supported on" ;;
    esac
}

# target/ dir is cached, so we need to remove old coverage files
cleanup_cov() {
    rm -rf ${TARGET_COV}
}


run_kcov() {
    KCOV="${KCOV:-kcov}"
    COVERALLS_ARG="${TRAVIS_JOB_ID:+--coveralls-id=$TRAVIS_JOB_ID}"
    EXAMPLES="${EXAMPLES:-demo}"

    # Build binaries
    cargo test --no-run -v
    for example in $EXAMPLES; do
        cargo build --example "$example"
    done

    EXAMPLE_BINS=$(echo "$EXAMPLES" | xargs -n1 | sed "s,^,${TARGET}/${PROFILE}/examples/,")
    mkdir -p "${TARGET_COV}"

    (
    set -x
    for file in ${TARGET}/${PROFILE}/${PROJECT_NAME}-*[^\.d] ${EXAMPLE_BINS} ; do
        "$KCOV" \
            $COVERALLS_ARG \
            --include-pattern=capstone-rs \
            --exclude-pattern=/.cargo,/usr/lib,/out/capstone.rs,capstone-sys \
            --verify "${TARGET_COV}" "$file"
    done
    )
}

cov() {
    echo "Running coverage"

    install_kcov
    cleanup_cov

    KCOV=./kcov-install/usr/local/bin/kcov run_kcov

    if [[ "${TRAVIS_JOB_ID:+Z}" = Z ]]; then
        bash <(curl -s https://codecov.io/bash)
        echo "Uploaded code coverage"
    else
        echo "Not uploading coverage since we are not in a CI job"
    fi
}

bench() {
    cargo bench
}

profile_args() {
    case "$PROFILE" in
    debug) ;;
    release) echo "--release" ;;
    *) Error "Unknown PROFILE $PROFILE" ;;
    esac
}

# Test rust file by making a temporary project
# Must have a main() function defined
test_rust_file() {
    (
    tmp_dir="$(mktemp -d /tmp/rust.testdir.XXXXXXXXXX)"
    [ -d "$tmp_dir" ] || Error "Could not make temp dir"

    capstone_dir="$(pwd)"
    cd "$tmp_dir"
    cargo new --bin test_project -v
    cd test_project
    echo "capstone = { path = \"$capstone_dir\" }" >> Cargo.toml
    cat Cargo.toml
    cat > src/main.rs
    pwd

    # Do not include features arguments
    cargo_cmd_args=(
        $(profile_args)
        --verbose
        )
    cargo check "${cargo_cmd_args[@]}" || exit 1

    rm -rf "$tmp_dir"
    ) || exit 1
}

run_tests() {
    TMPFILE="$(mktemp /tmp/capstone-rs.XXXXXXXXXX)"
    [ -f "$TMPFILE" ] || Error "Could not make temp file"
    for PROFILE in $PROFILES; do
        echo "Cargo tests without Valgrind"
        cargo_cmd_args=(
            $(profile_args)
            --features "$FEATURES"
            --verbose
            )
        expect_exit_status "$SHOULD_FAIL" \
            cargo test "${cargo_cmd_args[@]}" \
            --color=always -- --color=always \
            2>&1 | tee "$TMPFILE"
        # Use 2>&1 above instead of '|&' because OS X uses Bash 3

        cargo run "${cargo_cmd_args[@]}" --example demo
        cargo run "${cargo_cmd_args[@]}" --example cstool -- \
            --arch x86 --mode mode64 --file test-inputs/x86_64.bin_ls.bin |
            head -n20

        cat README.md | \
            sed -n '/^```rust/,/^```/p' | grep -vE '^```' | \
            test_rust_file


        if [ ! "${VALGRIND_TESTS}" ]; then
            continue
        fi

        test_binary="$(cat "$TMPFILE" |
            grep -E 'Running[^`]*`' |
            sed 's/^.*Running[^`]*`\([^` ]*\).*$/\1/' |
            grep -vE '^rustc|rustdoc$' |
            grep -E '/capstone-[^ -]+$'
            )"
        [ -f "$test_binary" ] ||
            Error "Unable to determine test binary (for Valgrind); found '$test_binary'"

        echo "Cargo tests WITH Valgrind"
        valgrind --error-exitcode=1 "$test_binary"
    done
    rm "$TMPFILE"
}

PROFILES="${PROFILES-debug release}"
for PROFILE in $PROFILES; do
    profile_args "$PROFILE"
done

# Note that `$PROFILE` is never in quotes so that it expands to nothing
# (not even an empty string argument) when the variable is empty. This is
# necessary so we don't pass an unexpected flag to cargo.


if [ $(basename "$0") = "test.sh" ]; then
    JOB="${JOB:-test}"

    set -x
    case "$JOB" in
        test)
            run_tests
            ;;
        valgrind-test)
            VALGRIND_TESTS=: run_tests
            ;;
        cov)
            PROFILE=debug $JOB
            ;;
        bench)
            PROFILE=release $JOB
            ;;
        *)
            echo "Error! Unknown \$JOB: '$JOB'"
            exit 1
    esac
fi

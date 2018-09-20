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

set -eu

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

PASS="PASS"
FAIL="FAIL"

if [ "$SHOULD_FAIL" ]; then
    EXPECTED_RESULT="$FAIL"
else
    EXPECTED_RESULT="$PASS"
fi

echo "Test should $EXPECTED_RESULT"

TRAVIS_OS_NAME="${TRAVIS_OS_NAME:-}"
if [ TRAVIS_OS_NAME ]; then
    case "$(uname)" in
    Linux) TRAVIS_OS_NAME=linux ;;
    Darwin) TRAVIS_OS_NAME=osx ;;
    *) Error "Unknown OS" ;;
    esac
fi

Error() {
    echo "Error:" "$@" 1>&2
    exit 1
}


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
    case "${TRAVIS_OS_NAME}" in
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
    rm -rf target/cov
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

    EXAMPLE_BINS=$(echo "$EXAMPLES" | xargs -n1 | sed "s,^,target/${PROFILE}/examples/,")
    mkdir -p "target/cov"

    (
    set -x
    for file in target/${PROFILE}/${PROJECT_NAME}-*[^\.d] ${EXAMPLE_BINS} ; do
        "$KCOV" \
            $COVERALLS_ARG \
            --exclude-pattern=/.cargo,/usr/lib,/out/capstone.rs \
            --verify "target/cov" "$file"
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

run_tests() {
    TMPFILE="$(mktemp /tmp/capstone-rs.XXXXXXXXXX)"
    [ -f "$TMPFILE" ] || Error "Could not make temp file"
    for PROFILE in $PROFILES; do
        echo "Cargo tests without Valgrind"
        expect_exit_status "$SHOULD_FAIL" \
            cargo test $(profile_args) \
            --features "$FEATURES" --verbose \
            --color=always -- --color=always \
            2>&1 | tee "$TMPFILE"
        # Use 2>&1 above instead of '|&' because OS X uses Bash 3

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

        install_valgrind
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

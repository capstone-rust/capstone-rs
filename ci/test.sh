#!/usr/bin/env bash
#
# Modified `ci/test.sh` from capstone-sys
# Environment variables:
#
# JOB: {*test,bench,cov}
# PROFILE: {*debug,release}
# SHOULD_FAIL: (disabled by default; set to non-empty string to enable)

set -eu
cd "$(dirname "$0")/.."

RUST_BACKTRACE=1
SHOULD_FAIL=${SHOULD_FAIL:-}  # Default to false
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

[ "${TRAVIS_OS_NAME-$(uname)}" = "linux" ] || :

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

cov() {
    cargo test --no-run

    wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
    tar xzf master.tar.gz
    cd kcov-master
    mkdir build
    cd build
    cmake ..
    make
    make install DESTDIR=../../kcov-build
    cd ../..
    rm -rf kcov-master
    for file in target/${PROFILE}/${PROJECT_NAME}-*[^\.d]; do
        mkdir -p "target/cov/$(basename $file)"
        ./kcov-build/usr/local/bin/kcov \
            --coveralls-id=$TRAVIS_JOB_ID \
            --exclude-pattern=/.cargo,/usr/lib \
            --verify "target/cov/$(basename $file)" "$file"
    done
    bash <(curl -s https://codecov.io/bash)
    echo "Uploaded code coverage"
}

bench() {
    cargo bench
}

PROFILE="${PROFILE-debug}"
case "$PROFILE" in
debug) PROFILE_ARGS= ;;
release) PROFILE_ARGS="--release" ;;
*) Error "Unknown PROFILE $PROFILE" ;;
esac

# Note that `$PROFILE` is never in quotes so that it expands to nothing
# (not even an empty string argument) when the variable is empty. This is
# necessary so we don't pass an unexpected flag to cargo.

JOB="${JOB-test}"
case "$JOB" in
    test)
        expect_exit_status "$SHOULD_FAIL" \
            cargo test $PROFILE_ARGS --features "$FEATURES" --verbose
        ;;
    cov|bench)
        $JOB
        ;;
    *)
        echo "Error! Unknown \$JOB: '$JOB'"
        exit 1
esac

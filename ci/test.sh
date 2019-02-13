#!/usr/bin/env bash
#
# Modified `ci/test.sh` from rust-bindgen
# Environment variables:
#
# RUST_PROFILE (required):
#     debug
#     release
#
# SHOULD_FAIL (defaults to false; set to enable)

set -eu
cd "$(dirname "$0")/.."

export RUST_BACKTRACE=1
export LLVM_VERSION="4.0.0"
export SHOULD_FAIL=${SHOULD_FAIL:-}  # Default to false

PASS="PASS"
FAIL="FAIL"

if [ "$SHOULD_FAIL" ]; then
    EXPECTED_RESULT="$FAIL"
else
    EXPECTED_RESULT="$PASS"
fi

echo "Test should $EXPECTED_RESULT"

if [ "${TRAVIS_OS_NAME}" = "linux" ]; then
    export PLATFORM="linux-gnu-ubuntu-14.04"
else
    export PLATFORM="apple-darwin"
fi

Error() {
    echo "Error:" "$@" 1>&2
    exit 1
}

llvm_download_if_needed() {
    export LLVM_VERSION_TRIPLE="${LLVM_VERSION}"
    export LLVM=clang+llvm-${LLVM_VERSION_TRIPLE}-x86_64-$1

    local llvm_build_dir="$HOME/.llvm-builds/${LLVM}"

    if [ -d "${llvm_build_dir}" ]; then
        echo "Using cached LLVM build for ${LLVM} in ${llvm_build_dir}";
    else
        wget http://llvm.org/releases/${LLVM_VERSION_TRIPLE}/${LLVM}.tar.xz
        mkdir -p "${llvm_build_dir}"
        tar -xf ${LLVM}.tar.xz -C "${llvm_build_dir}" --strip-components=1
    fi

    export LLVM_CONFIG_PATH="${llvm_build_dir}/bin/llvm-config"
    if [ "${TRAVIS_OS_NAME}" == "osx" ]; then
        cp "${llvm_build_dir}/lib/libclang.dylib" /usr/local/lib/libclang.dylib
    fi
}

# Install pre-reqs
test_setup() {
    for feature in "$@"; do
        case "$feature" in
        build_capstone_cmake)
            # Requirements already installed
            ;;
        use_system_capstone)
            # Install capstone to system ahead of time
            # @todo(tmfink) install capstone to system
            # pushd capstone
            # ./make.sh
            # ./make.sh install
            # popd
            ;;
        use_bindgen)
            # Install clang
            echo 'INSTALL CLANG'
            llvm_download_if_needed "$PLATFORM"
            ;;
        *)
            Error "Unknown feature '$feature'; update '$0'"
        esac
    done
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

case "$RUST_PROFILE" in
debug) RUST_PROFILE= ;;
release) RUST_PROFILE="--release" ;;
esac

# Note that `$RUST_PROFILE` is never in quotes so that it expands to nothing
# (not even an empty string argument) when the variable is empty. This is
# necessary so we don't pass an unexpected flag to cargo.

case "$CAPSTONE_SYS_JOB" in
    "test")
        test_setup $CAPSTONE_SYS_FEATURES
        expect_exit_status "$SHOULD_FAIL" \
            cargo test $RUST_PROFILE --features "$CAPSTONE_SYS_FEATURES" --verbose
        ;;

    *)
        echo "Error! Unknown \$CAPSTONE_SYS_JOB: '$CAPSTONE_SYS_JOB'"
        exit 1
esac

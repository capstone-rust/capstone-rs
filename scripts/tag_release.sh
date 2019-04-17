#!/bin/sh
#
# Tag the HEAD based on version in Cargo.toml

set -eu

cd "$(dirname $0)/.."

extract_toml_value() {
    grep "^$1" Cargo.toml | sed 's/^[^ =].*=.*"\([^"]\+\)"$/\1/' | head -n1
}

PACKAGE_NAME="$(extract_toml_value name)"
PACKAGE_VERSION="${PACKAGE_VERSION:-$(extract_toml_value version)}"
DESCRIPTION="${PACKAGE_NAME} v${PACKAGE_VERSION}"
TAG_NAME="${PACKAGE_NAME}-v${PACKAGE_VERSION}"
GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse HEAD)}"

echo "Commit log:"
git log -1 $GIT_COMMIT | cat

echo
echo -n "Create git tag: TAG_NAME=\"$TAG_NAME\" DESCRIPTION=\"$DESCRIPTION\" at $GIT_COMMIT? (y/N) "

read -r answer
case "$answer" in
    y|Y) ;;
    *)
        echo "Exiting"
        exit 1
        ;;
esac

set -x
git tag -s -m "${DESCRIPTION}" "${TAG_NAME}" "${GIT_COMMIT}"
set +x

echo
echo "Don't forget to push tags upstream:"
echo
echo "    git push origin --tags"

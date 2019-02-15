#!/bin/sh
#
# Tag the HEAD based on version in Cargo.toml

set -eu

cd "$(dirname $0)/.."

PACKAGE_VERSION="$(grep version Cargo.toml |
    sed 's/^version.*=.*"\([^"]\+\)"$/\1/' |
    head -n1)"
DESCRIPTION="Version ${PACKAGE_VERSION}"
TAG_NAME="v${PACKAGE_VERSION}"

echo "Last commit:"
git log -n1 | cat

echo
echo -n "Create git tag: TAG_NAME=\"$TAG_NAME\" DESCRIPTION=\"$DESCRIPTION\"? (y/N) "

read -r answer
case "$answer" in
    y|Y) ;;
    *)
        echo "Exiting"
        exit 1
        ;;
esac

set -x
git tag -s -m "${DESCRIPTION}" "${TAG_NAME}"
set +x

echo
echo "Don't forget to push tags upstream:"
echo
echo "    git push origin --tags"

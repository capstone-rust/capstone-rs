# Publish crates

## Changelog

```sh
# Update `CHANGELOG.md`
git commit
```

## For each crate:

For crates:
1. `capstone-sys`
2. `capstone-rs`:
3. `cstool`:

```sh
# Bump crate version:
# One of:
cargo set-version --bump major
cargo set-version --bump minor
cargo set-version --bump patch

git commit  # "${CRATE}: Bump version to ..."

# Add git tag:
./scripts/tag_release.sh

# Create fresh checkout (local clone from existing checkout)
git_dir="$(git rev-parse --show-toplevel)"
mkdir /tmp/pub
cd /tmp/pub
git clone "${git_dir}" capstone-rs

# Specify subdir with crate
cd capstone-rs/XYZ

# Publish to crates.io
cargo test
cargo publish
```

## Push Git changes

```
# Push commits/tags
git push
git push --tags
```
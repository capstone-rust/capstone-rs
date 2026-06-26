#!/usr/bin/env python3
"""Test capstone-rs with various feature combinations.

Tests:
  - all features disabled
  - all features enabled
  - each arch feature individually enabled
  - random subsets (2-arch and 3-arch combinations)
"""

import random
import re
import subprocess
import sys
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "capstone-rs" / "Cargo.toml"
CARGO = os.environ.get("CARGO", "cargo")

failed = []


def cargo_check(label, *args):
    cmd = [CARGO, "check", "--manifest-path", str(MANIFEST)] + list(args)
    print(f"\n=== {label} ===")
    print(f"    {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("    PASS")
    else:
        print(result.stdout)
        print(result.stderr)
        print("    FAIL")
        failed.append(label)


def get_arch_features():
    """Extract arch feature names from Cargo.toml."""
    text = MANIFEST.read_text()
    features = []
    for line in text.splitlines():
        m = re.match(r"^(arch_\w+) = \[\"capstone-sys/arch_", line)
        if m:
            features.append(m.group(1))
    return sorted(features)


def main():
    arch_features = get_arch_features()
    print(f"Found {len(arch_features)} arch features:")
    for f in arch_features:
        print(f"  {f}")

    # 1. All features disabled
    cargo_check("no-default-features", "--no-default-features")

    # 2. All features enabled
    cargo_check("all-features", "--all-features")

    # 3. Each arch feature individually
    base = "std,full"
    for feat in arch_features:
        cargo_check(
            f"only-{feat}",
            "--no-default-features",
            "--features",
            f"{base},{feat}",
        )

    # 4. Random subsets: shuffle each trial independently
    rng = random.Random(42)
    for trial in range(1, 6):
        shuffled = sorted(arch_features)
        rng.shuffle(shuffled)
        n = rng.choice([2, 3, 4, 5])
        subset = shuffled[:n]
        label = f"subset-trial{trial}-{n}arch"
        feats = f"{base},{','.join(subset)}"
        cargo_check(label, "--no-default-features", "--features", feats)

    print()
    print("=" * 50)
    if not failed:
        print("All feature combinations passed!")
    else:
        print(f"FAILED ({len(failed)}):")
        for f in failed:
            print(f"  {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Test capstone-rs with various feature combinations.

Tests:
  - all features disabled
  - all features enabled
  - each arch feature individually enabled
  - random subsets (2-5 arch features)
  - std/full on/off combinations
"""

import random
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "capstone-rs" / "Cargo.toml"
CARGO = "cargo"


def cargo_check(
    label: str,
    *,
    default_features: bool = True,
    all_features: bool = False,
    features: Optional[List[str]] = None,
) -> Optional[str]:
    args = ["--manifest-path", str(MANIFEST)]
    if all_features:
        args.append("--all-features")
    else:
        if not default_features:
            args.append("--no-default-features")
        if features:
            args.extend(["--features", ",".join(features)])

    cmd = [CARGO, "check"] + args
    print(f"\n=== {label} ===")
    print(f"    {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("    PASS")
        return None
    print(result.stdout)
    print(result.stderr)
    print("    FAIL")
    return label


def get_arch_features() -> List[str]:
    """Extract arch feature names from Cargo.toml."""
    text = MANIFEST.read_text()
    features = []
    for line in text.splitlines():
        m = re.match(r"^(arch_\w+) = \[\"capstone-sys/arch_", line)
        if m:
            features.append(m.group(1))
    return sorted(features)


def test_std_full_combos() -> List[str]:
    """Test various combinations of std and full being on/off."""
    failed: List[str] = []
    for std in (False, True):
        for full in (False, True):
            feats = []
            if std:
                feats.append("std")
            if full:
                feats.append("full")
            label = f"std={std},full={full}"
            result = cargo_check(
                label,
                default_features=False,
                features=feats or None,
            )
            if result:
                failed.append(result)
    return failed


def main() -> None:
    arch_features = get_arch_features()
    print(f"Found {len(arch_features)} arch features:")
    for f in arch_features:
        print(f"  {f}")

    failed: List[str] = []

    # 1. All features disabled
    r = cargo_check("no-default-features", default_features=False)
    if r:
        failed.append(r)

    # 2. All features enabled
    r = cargo_check("all-features", all_features=True)
    if r:
        failed.append(r)

    # 3. std/full combinations
    failed.extend(test_std_full_combos())

    # 4. Each arch feature individually
    for feat in arch_features:
        r = cargo_check(
            f"only-{feat}",
            default_features=False,
            features=["std", "full", feat],
        )
        if r:
            failed.append(r)

    # 5. Random subsets: shuffle each trial independently
    rng = random.Random(42)
    for trial in range(1, 6):
        shuffled = sorted(arch_features)
        rng.shuffle(shuffled)
        n = rng.choice([2, 3, 4, 5])
        subset = shuffled[:n]
        label = f"subset-trial{trial}-{n}arch"
        r = cargo_check(
            label,
            default_features=False,
            features=["std", "full", *subset],
        )
        if r:
            failed.append(r)

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

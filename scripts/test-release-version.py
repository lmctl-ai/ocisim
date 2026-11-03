#!/usr/bin/env python3
"""The committed public version floor plus run number yields stable versions."""
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
current = (root / "VERSION").read_text(encoding="utf-8").strip()
match = re.fullmatch(r"(0\.1)\.(\d+)", current)
assert match, current
patch = int(match[2])

def derive(*args):
    return subprocess.check_output(["bash", root / "scripts/derive-release-version.sh", *args], text=True).strip()

assert derive("--diagnostic") == current
assert derive("1") == f"0.1.{patch + 1}"
assert derive("19") == f"0.1.{patch + 19}"
assert derive("19") == f"0.1.{patch + 19}"
print("PASS ocisim run-derived version contract")

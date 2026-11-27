#!/usr/bin/env python3
"""Repository text policy check used in CI."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "__pycache__", "build", "dist", ".eggs", ".mypy_cache"}
failures = []

for directory, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.endswith(".egg-info")]
    for filename in filenames:
        if filename == ".DS_Store":
            continue
        path = os.path.join(directory, filename)
        with open(path, "rb") as handle:
            data = handle.read()
        if b"\x00" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        relative = os.path.relpath(path, ROOT)
        if "\u2013" in text or "\u2014" in text:
            failures.append(relative + ": contains an en dash or em dash")
        if "Co-Authored" + "-By:" in text:
            failures.append(relative + ": contains a co-author trailer")

if failures:
    for failure in failures:
        sys.stderr.write(failure + "\n")
    raise SystemExit(1)
sys.stdout.write("repository text policy checks passed\n")

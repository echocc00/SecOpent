#!/usr/bin/env python3
"""Pin sha256 digests for adapter images that currently use `:latest`.

Adapter images in ``image_catalog.py`` are digest-pinned for reproducibility +
supply-chain integrity, but 9 adapters still use ``digest=""`` (marked "TBD
when pulled" from A2). This script pulls each unpinned image and prints the
``ImageRef(...)`` line with the resolved digest, ready to paste into
``image_catalog.py``.

Run on a machine with Docker + internet (mirrors configured for CN networks):

    python3 scripts/pin_digests.py            # print lines to paste
    python3 scripts/pin_digests.py --apply    # auto-edit image_catalog.py

After pinning, commit the updated ``image_catalog.py``.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src" / "secopent" / "infrastructure" / "adapters" / "image_catalog.py"


def _unpinned_entries() -> list[tuple[str, str, str]]:
    """Return [(adapter_key, name, tag), ...] for entries with empty digest."""
    text = CATALOG.read_text(encoding="utf-8")
    # Matches: "key": ImageRef("name", "tag", ""),
    pattern = re.compile(r'"(\w+)":\s*ImageRef\("([^"]+)",\s*"([^"]+)",\s*""\)')
    return pattern.findall(text)


def _pull_and_digest(name: str, tag: str) -> str | None:
    """Pull name:tag and return its sha256 digest (or None on failure)."""
    ref = f"{name}:{tag}"
    print(f"  pulling {ref} ...", file=sys.stderr, flush=True)
    pull = subprocess.run(["docker", "pull", ref], capture_output=True, text=True)
    if pull.returncode != 0:
        print(f"  ERROR pulling {ref}: {pull.stderr.strip()}", file=sys.stderr)
        return None
    inspect = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", ref],
        capture_output=True, text=True,
    )
    if inspect.returncode != 0:
        return None
    digests = json.loads(inspect.stdout.strip())
    if not digests:
        return None
    # RepoDigests look like "name@sha256:abc..." - extract the sha256:... part.
    return digests[0].split("@", 1)[1]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true", help="edit image_catalog.py in place")
    args = ap.parse_args()

    entries = _unpinned_entries()
    if not entries:
        print("All adapter images already digest-pinned.")
        return 0

    print(f"Found {len(entries)} unpinned adapter image(s):\n", file=sys.stderr)
    pinned: dict[str, str] = {}
    for key, name, tag in entries:
        digest = _pull_and_digest(name, tag)
        if digest is None:
            print(f'  SKIP {key}: could not resolve digest', file=sys.stderr)
            continue
        pinned[key] = digest
        line = f'    "{key}": ImageRef("{name}", "{tag}", "{digest}"),'
        print(line)

    if not pinned:
        print("\nNo digests resolved (Docker unreachable or pulls failed).", file=sys.stderr)
        return 1

    if args.apply:
        text = CATALOG.read_text(encoding="utf-8")
        for key, digest in pinned.items():
            # Replace the specific empty-digest line for this key.
            old = re.compile(rf'("{key}":\s*ImageRef\("[^"]+",\s*"[^"]+",\s*)"",')
            text = old.sub(rf'\1"{digest}",', text)
        CATALOG.write_text(text, encoding="utf-8")
        print(f"\nUpdated {len(pinned)} digest(s) in {CATALOG.relative_to(ROOT)}", file=sys.stderr)
    else:
        print("\nRe-run with --apply to update image_catalog.py automatically.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

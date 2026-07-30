#!/usr/bin/env bash
# Release a SecOpent version: stamp the version single-source, close the
# CHANGELOG section, commit, tag v<version>, push, and open a GitHub Release
# whose notes are extracted from CHANGELOG.md (T9 / §②).
#
# Usage: scripts/release.sh <version>      e.g. scripts/release.sh 1.1.0-stable
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: scripts/release.sh <version>   (e.g. 1.1.0-stable)" >&2
  exit 2
fi
TAG="v${VERSION}"
DATE="$(date +%Y-%m-%d)"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION_FILE="src/secopent/__version__.py"
CHANGELOG="CHANGELOG.md"

# Refuse to release from a dirty tree or onto an existing tag.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree not clean; commit or stash first" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  echo "error: tag ${TAG} already exists" >&2
  exit 1
fi

echo ">> stamping version ${VERSION} in ${VERSION_FILE}"
# Replace the __version__ = "..." assignment, whatever its current value.
sed -i.bak -E "s/^__version__ = \".*\"/__version__ = \"${VERSION}\"/" "$VERSION_FILE"
rm -f "${VERSION_FILE}.bak"

echo ">> closing CHANGELOG [Unreleased] -> [${VERSION}] - ${DATE}"
# Insert the dated release heading directly under the [Unreleased] heading.
sed -i.bak -E "s|^## \[Unreleased\]$|## [Unreleased]\n\n## [${VERSION}] - ${DATE}|" "$CHANGELOG"
rm -f "${CHANGELOG}.bak"

echo ">> committing"
git add "$VERSION_FILE" "$CHANGELOG"
git commit -m "release: v${VERSION}"

echo ">> tagging ${TAG}"
git tag -a "$TAG" -m "SecOpent ${VERSION}"

echo ">> pushing commit + tag"
git push
git push origin "$TAG"

# Extract this release's CHANGELOG section as the release notes. The heading is
# "## [VERSION] - DATE", so match by prefix (index==1), not exact equality.
NOTES="$(awk -v ver="## [${VERSION}]" '
  index($0, ver) == 1 { capture = 1; next }
  capture && /^## \[/ { exit }
  capture { print }
' "$CHANGELOG")"

if command -v gh >/dev/null 2>&1; then
  echo ">> creating GitHub Release ${TAG}"
  gh release create "$TAG" --title "SecOpent ${VERSION}" --notes "${NOTES}"
else
  echo ">> gh CLI not found; tag pushed. Create the GitHub Release manually with:"
  echo "----- release notes for ${TAG} -----"
  echo "${NOTES}"
fi

echo ">> released ${TAG}"

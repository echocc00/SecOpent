"""Integration tests for SubprocessContainerExecutor (Phase A Task A2).

These run REAL Docker containers (marked ``integration``; auto-skipped without
Docker by ``conftest.py``). They verify the executor runs digest-pinned tool
images under the §8.4 hardening flags:

1. nuclei runs against httpbin (via a self-contained mounted template - the
   nuclei image ships no templates and GitHub template download is unavailable
   in this network, so the test mounts a minimal template);
2. the container runs as non-root (uid 65532);
3. a digest mismatch is rejected before execution (supply-chain guard);
4. cloud-metadata (169.254.169.254) is not reachable from the bridge network
   (network-layer isolation is strengthened to nftables in M5).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.infrastructure.adapters.image_catalog import IMAGE_CATALOG
from secopent.infrastructure.adapters.subprocess_executor import (
    ImageDigestMismatch,
    SubprocessContainerExecutor,
)

# A minimal, self-contained nuclei template (no template download needed): it
# requests httpbin's /status/200 and matches a 200 response, producing a finding.
_NUCLEI_TEMPLATE = """\
id: httpbin-status
info:
  name: httpbin status 200
  author: secopent
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/status/200"
    matchers:
      - type: status
        status:
          - 200
"""


def _mounts(tmp_path: Path) -> dict[str, str]:
    (tmp_path / "input").mkdir(exist_ok=True)
    (tmp_path / "output").mkdir(exist_ok=True)
    return {
        "/work/input": str(tmp_path / "input"),
        "/work/output": str(tmp_path / "output"),
    }


@pytest.mark.integration
def test_runs_nuclei_against_httpbin(tmp_path: Path) -> None:
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "httpbin-status.yaml").write_text(_NUCLEI_TEMPLATE, encoding="utf-8")
    mounts = _mounts(tmp_path)
    mounts["/templates"] = str(templates)

    nuclei = IMAGE_CATALOG["nuclei"]
    executor = SubprocessContainerExecutor(default_timeout=180)
    result = executor.run(
        image_digest=f"{nuclei.name}@{nuclei.digest}",
        command=[
            "-t",
            "/templates/httpbin-status.yaml",
            "-u",
            "http://host.docker.internal:8080",
            "-jsonl",
            "-silent",
            "-duc",
        ],
        mounts=mounts,
        network_policy="bridge",
        resource_limits={"memory": "512m", "cpus": "0.5"},
    )
    assert result.exit_code == 0, f"nuclei failed: {result.stderr[:500]}"
    # nuclei emits the finding as JSONL on stdout (template id present).
    assert "httpbin-status" in result.stdout, f"no finding in output: {result.stdout[:500]}"


@pytest.mark.integration
def test_enforces_security_flags_nonroot(tmp_path: Path) -> None:
    alpine = IMAGE_CATALOG["alpine"]
    executor = SubprocessContainerExecutor()
    result = executor.run(
        image_digest=f"{alpine.name}@{alpine.digest}",
        command=["id"],
        mounts=_mounts(tmp_path),
        network_policy="bridge",
        resource_limits={"memory": "64m", "cpus": "0.1"},
    )
    assert result.exit_code == 0, f"id failed: {result.stderr}"
    assert "65532" in result.stdout, f"nonroot uid not found: {result.stdout}"


@pytest.mark.integration
def test_digest_mismatch_rejected(tmp_path: Path) -> None:
    executor = SubprocessContainerExecutor()
    bad_ref = "alpine@sha256:" + "0" * 64
    with pytest.raises(ImageDigestMismatch):
        executor.run(
            image_digest=bad_ref,
            command=["echo", "should-not-run"],
            mounts=_mounts(tmp_path),
            network_policy="bridge",
            resource_limits={"memory": "64m", "cpus": "0.1"},
        )


@pytest.mark.integration
def test_scoped_egress_blocks_metadata(tmp_path: Path) -> None:
    """Cloud metadata 169.254.169.254 is not routable from the bridge network.

    Docker's bridge does not route link-local (169.254.0.0/16), so the request
    fails and the container reports BLOCKED. M5 strengthens this to explicit
    nftables/netns blocking regardless of routing.
    """
    alpine = IMAGE_CATALOG["alpine"]
    executor = SubprocessContainerExecutor(default_timeout=60)
    result = executor.run(
        image_digest=f"{alpine.name}@{alpine.digest}",
        command=[
            "sh",
            "-c",
            "wget -T 3 -q http://169.254.169.254/ && echo REACHABLE || echo BLOCKED",
        ],
        mounts=_mounts(tmp_path),
        network_policy="bridge",
        resource_limits={"memory": "64m", "cpus": "0.1"},
    )
    assert "BLOCKED" in result.stdout, f"metadata unexpectedly reachable: {result.stdout}"

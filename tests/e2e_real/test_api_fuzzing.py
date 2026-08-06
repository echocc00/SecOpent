"""Real e2e tests for the API fuzzing adapters: Schemathesis + RESTler.

Phase 2.7 (RESTler) + 2.8 (Schemathesis) of the M5 milestone. These tests
verify the real execution chain is wired end-to-end:

- **Schemathesis**: real schemathesis container (digest-pinned) fuzzes the
  live httpbin target's OpenAPI spec -> NDJSON events on stdout -> parser
  extracts failed checks -> Observations.
- **RESTler**: requires an OpenAPI spec + grammar compilation step that is
  too heavy for an in-test setup. We document the operator-driven run steps
  and skip honestly rather than fake a pass.

Marked ``e2e_real``; skipped automatically when Docker or a target is down.
"""
from __future__ import annotations

import pytest

from secopent.domain.adapters.contracts import CoverageDomain
from secopent.infrastructure.adapters.real_scan import _ADAPTER_PARSERS, RealScanRunner

# Schemathesis NDJSON report written to /dev/stdout inside the container so the
# RealScanRunner captures it as stdout. We request a minimal fuzzing run: 5
# examples, only the ``not_a_server_error`` check, fuzzing phase only.
_SCHEMATHESIS_ARGS = [
    "run",
    "--no-color",
    "--url", "http://host.docker.internal:8080",
    "--checks", "not_a_server_error",
    "--max-examples", "5",
    "--phases", "fuzzing",
    "--report", "ndjson",
    "--report-ndjson-path", "/dev/stdout",
    "http://host.docker.internal:8080/spec.json",
]


@pytest.mark.e2e_real
def test_schemathesis_real_fuzz_httpbin(require_target) -> None:
    """Run a real schemathesis fuzzing scan against httpbin's OpenAPI spec.

    httpbin's spec has known schema issues (path params not declared, ``int``
    instead of ``integer``) that cause some endpoints to error, but the
    fuzzing phase still tests ~60 operations and finds 5xx server errors on
    valid inputs (``not_a_server_error`` check). The parser must extract at
    least one Observation from the real NDJSON output.

    Schemathesis exits non-zero when failures are found; that is expected
    here (we WANT it to find bugs). The test asserts the parser produced
    Observations, not that exit_code == 0.
    """
    httpbin_url = require_target("httpbin")
    _ = httpbin_url  # guards the skip; the scan targets host.docker.internal
    runner = RealScanRunner(default_timeout=300)
    result = runner.scan(
        adapter_key="schemathesis",
        args=_SCHEMATHESIS_ARGS,
        mounts=None,  # no bind mounts needed; /dev/stdout is in-container
    )
    # Schemathesis exits 1 when failures are found (expected for httpbin).
    # Exit 0 means no failures found (also valid if httpbin is clean). Any
    # other exit code indicates a crash/timeout.
    assert result.exit_code in (0, 1), (
        f"schemathesis crashed (exit={result.exit_code}): {result.stderr[-500:]}"
    )
    # The parser must have extracted at least one Observation from the real
    # NDJSON output. httpbin's /redirect-to endpoint reliably 500s under
    # fuzzing, so we expect at least one not_a_server_error failure.
    assert result.observations, (
        "no Observations parsed from real schemathesis output; "
        f"stdout tail: {result.stdout[-300:]}"
    )
    obs = result.observations[0]
    assert obs.coverage_domain is CoverageDomain.WEB
    assert obs.rule_id.startswith("schemathesis.")
    # test_class=boundary must be surfaced for CoverageMatrix attribution.
    assert str(obs.raw.get("test_class", "")).lower() == "boundary"


@pytest.mark.e2e_real
def test_restler_real_scan_deferred(require_target) -> None:
    """RESTler requires an OpenAPI spec + grammar compilation step that is
    too heavy for an in-test setup.

    RESTler's workflow is:
    1. ``Restler compile --api_spec openapi.json`` to generate a grammar dir.
    2. ``Restler fuzz --grammar_dir`` to run the stateful sequence fuzzer.
    3. The fuzzing run writes ``bugs.json`` to an engine working directory.

    This requires a multi-step preparation (compile then fuzz) with mounted
    grammar/engine dirs, which is beyond what a single ``docker run`` can do.
    The RESTler adapter parser (``restler.parse``) is tested via fixtures
    (``tests/adapter_contract/test_web_api_adapters.py``) and registered in
    ``RealScanRunner._ADAPTER_PARSERS``; the real fuzzing run is deferred to
    operator-driven execution with a provisioned grammar dir.

    This test is a documented skip (honest skip > fake pass) that verifies
    the parser IS registered in the runner, so the wiring is complete and
    only the runtime setup is deferred.
    """
    require_target("httpbin")  # guards skip: target must be up to be relevant
    # Verify the RESTler parser is registered (wiring is complete).
    assert "restler" in _ADAPTER_PARSERS, (
        "RESTler parser must be registered in RealScanRunner._ADAPTER_PARSERS"
    )
    pytest.skip(
        "RESTler requires OpenAPI spec + grammar compilation (Restler compile) "
        "before fuzzing; deferred to operator-driven run with a provisioned "
        "grammar dir. Parser is registered and fixture-tested."
    )

## Summary

<!-- What changed and why (1-3 sentences). Link the spec/plan/issue. -->

## End-to-end impact (integration graph)

- [ ] I checked `docs/architecture/integration-graph.md`.
- [ ] This PR changes NO node/edge in the graph, OR the graph + edge coverage
      table are updated in this PR.
- [ ] Every new/changed edge has a test reference (no silent `**GAP**`s).

Which end-to-end path does this change affect? (assessment execution / audit /
oracle / API-only / none)

## Forbidden-pattern self-check

- [ ] No raw `threading.Thread` in routers (use BackgroundTasks)
- [ ] No `.open_session()` on hot paths (use the caller's session / UnitOfWork)
- [ ] Audit `.record(...)` calls thread `session=` (run
      `python scripts/lint_forbidden_patterns.py`)

## Test plan

- [ ] `py -3.12 -m pytest -q` (default tier) passes
- [ ] `py -3.12 -m pytest -m realism -q` passes if DB/audit/concurrency touched
- [ ] `ruff check src tests` + `mypy src/secopent` + `bandit -r src/secopent -ll` pass
- [ ] New behavior has tests (AAA, descriptive names); coverage >= 80%

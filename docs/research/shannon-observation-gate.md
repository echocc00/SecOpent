# Shannon Observation Gate Evaluation

> **Purpose**: Record the structured evaluation of Shannon as a white-box peer
> agent candidate. Fill in after running Shannon against crAPI (or equivalent)
> with P2 A/B baseline data available.

## Inputs

| Input | Source | Status |
|-------|--------|--------|
| P2 A/B baseline (Strix black-box findings) | `docs/research/strix-ab-baseline.md` | _pending_ |
| Shannon white-box run results (crAPI) | `.shannon/deliverables/` from live run | _pending_ |
| Strix + Shannon combined findings | Post-normalization observation set | _pending_ |
| Per-run cost (LLM tokens + wall clock) | PeerAgentReport audit trail | _pending_ |

## Criteria

| # | Criterion | Threshold | Weight |
|---|-----------|-----------|--------|
| 1 | White-box incremental findings > 0 | At least 1 confirmed finding not found by Strix alone | HIGH |
| 2 | Overlap with Strix black-box results | < 80% overlap (i.e., >= 20% unique value) | MEDIUM |
| 3 | Single-run cost | <= $5 USD equivalent LLM tokens | MEDIUM |
| 4 | Wall-clock time | <= 60 minutes per target app | LOW |
| 5 | False positive rate (normalized) | <= 30% of Shannon findings rejected at gate | MEDIUM |
| 6 | Operational complexity | Manageable within current harness (no custom infra) | LOW |

## Decision

_Select one after filling in the criteria above:_

- [ ] **Retain as white-box备选**: Shannon provides sufficient incremental value to justify ongoing integration
- [ ] **Downgrade to on-demand only**: Useful for specific scenarios but not default peer agent
- [ ] **Do not adopt**: Insufficient value or excessive cost/complexity

### Rationale

_Free-text justification referencing the criteria above._

```
(To be filled after evaluation run)
```

## Signature

| Role | Name | Date | Decision |
|------|------|------|----------|
| Tech Lead | | | |
| Security Engineer | | | |
| Product Owner | | | |

---

**Last updated**: 2026-08-04 (template created; evaluation pending environment readiness)

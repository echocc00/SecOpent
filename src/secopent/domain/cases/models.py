# src/secopent/domain/cases/models.py
"""Case domain models (§11.2/§11.5): versioned, signed verification recipes.

A ``CaseDefinition`` is a Nuclei-compatible YAML case plus three SecOpent
extension hooks (a ``{{canary_token}}`` placeholder, a ``verification`` block,
and a ``classification`` block). Cases move through a lifecycle
(DRAFT -> VALIDATED -> REVIEWED -> SIGNED -> PUBLISHED, plus DISABLED /
DEPRECATED terminal states). Each version records author, declared risk, target
type, schema, preconditions, steps, assertions, evidence requirements,
CWE/CVE/OWASP mapping, signature, and minimum engine version.

The declared ``risk`` must never be lower than the statically computed risk
(enforced by the RiskAnalyzer at publish time - §11.6).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..common.errors import DomainValidationError
from ..policy.models import RiskClass


class CaseStatus(StrEnum):
    """YAML-case lifecycle states (§11.5)."""

    DRAFT = "draft"
    VALIDATED = "validated"
    REVIEWED = "reviewed"
    SIGNED = "signed"
    PUBLISHED = "published"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class CaseOrigin(StrEnum):
    """Where a case came from (affects review strictness)."""

    MANUAL = "manual"
    MODEL_GENERATED = "model_generated"
    COMMUNITY = "community"


@dataclass(frozen=True, slots=True)
class CaseStep:
    """One DSL action in a case (interpreted by the case engine, §11.3).

    ``action`` is the DSL verb (e.g. ``http.request``, ``dns.resolve``,
    ``oast.wait``); ``spec`` carries the action's parameters (method, path,
    extractors, ...). The domain stores the spec as an opaque mapping - the
    case engine validates and executes it.
    """

    id: str
    action: str
    spec: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("CaseStep.id must be non-empty")
        if not self.action:
            raise DomainValidationError("CaseStep.action must be non-empty")


@dataclass(frozen=True, slots=True)
class CaseAssertion:
    """A post-step assertion, evaluated by the internal AST (never ``eval``)."""

    id: str
    expression: str

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("CaseAssertion.id must be non-empty")
        if not self.expression:
            raise DomainValidationError("CaseAssertion.expression must be non-empty")


@dataclass(frozen=True, slots=True)
class CaseVerification:
    """The ``verification`` extension block: links the VerificationMethodRegistry.

    ``method`` is the vuln type whose VerificationMethod governs N/N; ``reproduce``
    is the required independent reproduction count (must be >= 1, and the oracle
    will also honour the method's own ``default_n``).
    """

    method: str
    reproduce: int

    def __post_init__(self) -> None:
        if not self.method:
            raise DomainValidationError("CaseVerification.method must be non-empty")
        if self.reproduce < 1:
            raise DomainValidationError("CaseVerification.reproduce must be >= 1")


@dataclass(frozen=True, slots=True)
class CaseDefinition:
    """A versioned case definition (§11.5 record fields)."""

    id: str
    version: str
    author: str
    risk: RiskClass
    target_type: str
    schema: str
    steps: tuple[CaseStep, ...]
    preconditions: tuple[str, ...] = ()
    assertions: tuple[CaseAssertion, ...] = ()
    evidence_req: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    verification: CaseVerification | None = None
    signature: str = ""
    min_engine_version: str = "1.0.0"
    origin: CaseOrigin = CaseOrigin.MANUAL
    status: CaseStatus = CaseStatus.DRAFT
    # The Nuclei-compatible YAML source of the case (decision D: the backend
    # stores the editable YAML; CaseStudio's Monaco editor reads/writes this).
    yaml: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("CaseDefinition.id must be non-empty")
        if not self.version:
            raise DomainValidationError("CaseDefinition.version must be non-empty")
        if not self.author:
            raise DomainValidationError("CaseDefinition.author must be non-empty")
        if not self.target_type:
            raise DomainValidationError("CaseDefinition.target_type must be non-empty")
        if not self.schema:
            raise DomainValidationError("CaseDefinition.schema must be non-empty")
        if not self.steps:
            raise DomainValidationError("CaseDefinition.steps must be non-empty")

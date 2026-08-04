"""CoreSignedAuditEvent ORM registration (W3-C T2)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from secopent.infrastructure.db import signed_audit_models  # noqa: F401
from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.sqlite import create_sqlite_engine


def test_table_registered_on_metadata() -> None:
    assert "core_signed_audit_events" in CoreBase.metadata.tables


def test_create_all_builds_table(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "signed.db")
    CoreBase.metadata.create_all(engine)
    with Session(engine) as session:
        from secopent.infrastructure.db.signed_audit_models import (
            CoreSignedAuditEvent,
        )

        row = CoreSignedAuditEvent(
            event_id="evt-1",
            actor="a",
            action="x",
            resource_type="r",
            resource_id="1",
            payload={"k": "v"},
            previous_hash="0" * 64,
            event_hash="sha256:" + "a" * 64,
            occurred_at=__import__("datetime").datetime(2026, 1, 1),
            signature="ff",
        )
        session.add(row)
        session.commit()
        loaded = session.get(CoreSignedAuditEvent, 1)
    assert loaded is not None
    assert loaded.signature == "ff"
    assert loaded.event_id == "evt-1"

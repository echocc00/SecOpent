"""alembic baseline schema equivalence (W4-D T4).

The production schema source of truth is alembic (``secopent db upgrade``);
``create_all`` is the dev/test path. The two must produce the same schema, else
a DB bootstrapped one way can't be migrated the other. This test compares
table + column names between a ``create_all`` DB and an ``alembic upgrade``
DB. If they diverge (e.g. a new ORM table not yet in the baseline migration),
regenerate or extend the baseline.
"""
from __future__ import annotations

from sqlalchemy import create_engine, inspect

from secopent.infrastructure.db import session as _session  # noqa: F401 - registers models
from secopent.infrastructure.db.core_models import CoreBase
from secopent.interfaces.cli.main import main

_SKIP = frozenset({"alembic_version", "core_vulnerabilities_fts"})


def _schema(url: str) -> dict[str, set[str]]:
    eng = create_engine(url)
    insp = inspect(eng)
    return {
        t: {c["name"] for c in insp.get_columns(t)}
        for t in insp.get_table_names()
        if t not in _SKIP
    }


def test_alembic_baseline_matches_create_all(tmp_path) -> None:  # type: ignore[no-untyped-def]
    url_a = f"sqlite:///{(tmp_path / 'a.db').as_posix()}"
    eng_a = create_engine(url_a)
    CoreBase.metadata.create_all(eng_a)
    schema_a = _schema(url_a)

    url_b = f"sqlite:///{(tmp_path / 'b.db').as_posix()}"
    rc = main(["db", "upgrade", "--db", url_b])
    assert rc == 0
    schema_b = _schema(url_b)

    only_create_all = set(schema_a) - set(schema_b)
    only_alembic = set(schema_b) - set(schema_a)
    assert not only_create_all, (
        f"tables only in create_all (missing from alembic baseline): "
        f"{sorted(only_create_all)}"
    )
    assert not only_alembic, (
        f"tables only in alembic baseline (removed from ORM): "
        f"{sorted(only_alembic)}"
    )
    for table in schema_a:
        assert schema_a[table] == schema_b[table], (
            f"column mismatch in {table}: "
            f"only in create_all={schema_a[table] - schema_b[table]}, "
            f"only in alembic={schema_b[table] - schema_a[table]}"
        )

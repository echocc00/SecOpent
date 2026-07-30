#!/usr/bin/env python
"""Wrapper for the SecOpent SQLite -> PostgreSQL data migration (T15).

See ``src/secopent/scripts/migrate_db.py`` for the implementation.

Usage:
    python scripts/migrate_sqlite_to_pg.py --source secopent.db \
        --dest "postgresql+psycopg://user:pass@host:5432/secopent"
"""
from __future__ import annotations

from secopent.scripts.migrate_db import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

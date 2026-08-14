"""grant rows

Adds ``core_grants`` - the human-granted authorization boundary that lets an
agent approve/start assessments within a scope+risk+window (v0.6.0 Phase A,
spec §3.6). The embedded ScopeSnapshot reuses ``core_scope_snapshots``; the
grant row references it by the snapshot primary key ``id`` (not digest).
(sepcs/2026-08-08-engagement-grant-mission-design.md)

Revision ID: <generated>
Revises: 3f91c2a7d504
Create Date: 2026-08-08
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'bd0a1c2e3f40'
down_revision: str | None = '3f91c2a7d504'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Idempotent: a DB bootstrapped by create_all of a version that already
    # carries core_grants (F4 autostamp path) must not fail with "table
    # already exists" when `secopent db upgrade` runs (v0.4.0 P1 class).
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "core_grants" in inspector.get_table_names():
        return
    op.create_table(
        'core_grants',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('project_id', sa.String(length=64),
                  sa.ForeignKey('core_projects.id'), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('scope_snapshot_id', sa.String(length=64),
                  sa.ForeignKey('core_scope_snapshots.id'), nullable=False),
        sa.Column('risk_caps', sa.Text(), nullable=False),
        sa.Column('valid_from', sa.DateTime(), nullable=False),
        sa.Column('valid_to', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(length=12), nullable=False),
        sa.Column('digest', sa.String(length=80), nullable=False),
    )
    op.create_index('ix_core_grants_project_id', 'core_grants', ['project_id'])
    op.create_index('ix_core_grants_digest', 'core_grants', ['digest'])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "core_grants" in inspector.get_table_names():
        op.drop_table('core_grants')
"""assessment control column

Adds ``core_assessments.control`` - the durable runtime-control signal for a
live assessment (MCP pause/resume/cancel; ControlState). Backfilled with
``none`` so existing rows are equivalent to "no signal".
(sepcs/2026-08-13-mcp-job-lease-cancellation-design.md, M3)

Revision ID: 3f91c2a7d504
Revises: 811a5b9a583d
Create Date: 2026-08-13
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3f91c2a7d504'
down_revision: Union[str, None] = '811a5b9a583d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotent: a pre-alembic (v0.2.x) DB bootstrapped by the CURRENT
    # create_all may already carry the column (F4 autostamp path); the
    # operator's `secopent db upgrade` must not fail with "duplicate column".
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {c["name"] for c in inspector.get_columns("core_assessments")}
    if "control" not in columns:
        op.add_column(
            'core_assessments',
            sa.Column('control', sa.String(length=32), nullable=False,
                      server_default='none'),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {c["name"] for c in inspector.get_columns("core_assessments")}
    if "control" in columns:
        op.drop_column('core_assessments', 'control')
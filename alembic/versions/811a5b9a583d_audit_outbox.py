"""audit outbox

Revision ID: 811a5b9a583d
Revises: ad674b51adca
Create Date: 2026-08-05 23:45:05.301245
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '811a5b9a583d'
down_revision: Union[str, None] = 'ad674b51adca'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('core_audit_outbox',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('actor', sa.String(length=64), nullable=False),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('resource_type', sa.String(length=64), nullable=False),
    sa.Column('resource_id', sa.String(length=64), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_core_audit_outbox_status'), 'core_audit_outbox', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_core_audit_outbox_status'), table_name='core_audit_outbox')
    op.drop_table('core_audit_outbox')

"""core_reasoning_loops + core_loop_steps (v0.7.8, spec §12.1).

Persists the ReasoningLoop snapshot (one row per loop) and its append-only
per-step audit records, so the SQLAlchemy-backed repositories can replace the
in-memory stores in production (v0.7.8 Task 1).

The spec §12.1 table design was a starting point: it omitted several
``LoopState`` fields (``consecutive_no_signal``, ``consecutive_policy_rejected``,
``last_step_at``, and the v0.7.7 pause-tracking fields) that would break
full-fidelity ``repo.get(state) == state`` round-trips. Those are added here so
the persisted row carries EVERY field of the frozen ``LoopState`` dataclass.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd3f4a5b6c7d8'
down_revision: str | None = 'bd0a1c2e3f40'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Idempotent: a DB bootstrapped by create_all of a version that already
    # carries these tables must not fail with "table already exists" when
    # `secopent db upgrade` runs (v0.4.0 P1 class; mirrors grants template).
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "core_reasoning_loops" in inspector.get_table_names():
        return
    op.create_table(
        'core_reasoning_loops',
        sa.Column('loop_id', sa.String(length=64), primary_key=True),
        sa.Column('assessment_id', sa.String(length=64),
                  sa.ForeignKey('core_assessments.id'), nullable=False),
        sa.Column('phase', sa.String(length=32), nullable=False),
        sa.Column('policy_snapshot', sa.String(length=64), nullable=False),
        sa.Column('budget_state', sa.JSON(), nullable=False),  # LoopBudget serialized
        sa.Column('context_hash', sa.String(length=64), nullable=False),
        sa.Column('catalog_required_remaining', sa.JSON(), nullable=False),
        sa.Column('catalog_required_executed', sa.JSON(), nullable=False),
        sa.Column('consecutive_no_signal', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('consecutive_policy_rejected', sa.Integer(), nullable=False,
                  server_default='0'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_step_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('pause_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('paused_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('correlation_id', sa.String(length=64), nullable=False),
        sa.UniqueConstraint('assessment_id', 'loop_id', name='uq_loops_assessment_loop'),
    )
    op.create_index('ix_loops_assessment', 'core_reasoning_loops',
                    ['assessment_id', 'phase'])

    op.create_table(
        'core_loop_steps',
        sa.Column('step_id', sa.String(length=64), primary_key=True),
        sa.Column('loop_id', sa.String(length=64),
                  sa.ForeignKey('core_reasoning_loops.loop_id'), nullable=False),
        sa.Column('step_number', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('context_hash_before', sa.String(length=64), nullable=False),
        sa.Column('proposed_action', sa.JSON(), nullable=False),  # ProposeAction
        sa.Column('propose_tokens_used', sa.Integer(), nullable=False),
        sa.Column('propose_latency_ms', sa.Integer(), nullable=False),
        sa.Column('propose_rationale', sa.Text(), nullable=True),
        sa.Column('schema_check_passed', sa.Boolean(), nullable=False),
        sa.Column('policy_decision', sa.JSON(), nullable=False),  # PolicyDecision
        sa.Column('permit_id', sa.String(length=64), nullable=True),
        sa.Column('tool_or_case_id', sa.String(length=64), nullable=True),
        sa.Column('execution_result', sa.JSON(), nullable=True),
        sa.Column('evidence_refs', sa.JSON(), nullable=True),
        sa.Column('observation_signals', sa.JSON(), nullable=True),
        sa.Column('catalog_class_matched', sa.JSON(), nullable=True),
        sa.Column('oracle_progressed', sa.Boolean(), nullable=False,
                  server_default=sa.text('false')),
        sa.Column('correlation_id', sa.String(length=64), nullable=False),
        sa.UniqueConstraint('loop_id', 'step_number', name='uq_loop_steps_loop_number'),
    )
    op.create_index('ix_loop_steps_loop', 'core_loop_steps', ['loop_id', 'step_number'])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "core_loop_steps" in inspector.get_table_names():
        op.drop_index('ix_loop_steps_loop', table_name='core_loop_steps')
        op.drop_table('core_loop_steps')
    if "core_reasoning_loops" in inspector.get_table_names():
        op.drop_index('ix_loops_assessment', table_name='core_reasoning_loops')
        op.drop_table('core_reasoning_loops')

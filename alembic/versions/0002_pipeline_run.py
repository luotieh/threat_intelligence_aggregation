"""pipeline run log

规则生成的运行日志:富化 / LLM 描述 / 写 yaml/zip 各步的实际结果。
取代原先"事后扫磁盘反推"的归档审计(archive + audit.jsonl,已移除)。

Revision ID: 0002_pipeline_run
Revises: 0001_initial
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_pipeline_run"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pipeline_run",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("trigger", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("target", sa.Integer()),
        sa.Column("type_quota", sa.JSON()),
        sa.Column("otx_pull_rounds", sa.Integer()),
        sa.Column("enrich_attempts", sa.Integer()),
        sa.Column("confirmed", sa.Integer()),
        sa.Column("confirmed_by_type", sa.JSON()),
        sa.Column("otx_only", sa.Integer()),
        sa.Column("narrated", sa.Integer()),
        sa.Column("narrate_failed", sa.Integer()),
        sa.Column("narrate_missing", sa.Integer()),
        sa.Column("pushed", sa.Integer()),
        sa.Column("pushed_by_type", sa.JSON()),
        sa.Column("files", sa.JSON()),
        sa.Column("rules", sa.JSON()),
        sa.Column("notes", sa.JSON()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_pipeline_run_started_at", "pipeline_run", ["started_at"])


def downgrade():
    op.drop_index("idx_pipeline_run_started_at", table_name="pipeline_run")
    op.drop_table("pipeline_run")

"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-09
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "intel_indicator",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("misp_event_id", sa.Text()),
        sa.Column("misp_event_uuid", sa.String(64)),
        sa.Column("misp_attribute_uuid", sa.String(64), unique=True),
        sa.Column("platform_category", sa.String(32), nullable=False),
        sa.Column("misp_category", sa.Text()),
        sa.Column("misp_type", sa.String(128), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("normalized_type", sa.String(128)),
        sa.Column("normalized_value", sa.Text()),
        sa.Column("to_ids", sa.Boolean(), default=False),
        sa.Column("tlp", sa.String(32)),
        sa.Column("confidence", sa.Integer()),
        sa.Column("threat_level", sa.String(64)),
        sa.Column("severity", sa.String(32)),
        sa.Column("first_seen", sa.DateTime(timezone=True)),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("valid_until", sa.DateTime(timezone=True)),
        sa.Column("source_org", sa.Text()),
        sa.Column("tags", sa.JSON()),
        sa.Column("galaxies", sa.JSON()),
        sa.Column("raw", sa.JSON()),
        sa.Column("pushed_to_ta_node", sa.Boolean(), default=False),
        sa.Column("pushed_at", sa.DateTime(timezone=True)),
        sa.Column("push_error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_intel_platform_category", "intel_indicator", ["platform_category"])
    op.create_index("idx_intel_misp_type", "intel_indicator", ["misp_type"])
    op.create_index("idx_intel_normalized_value", "intel_indicator", ["normalized_value"])
    op.create_index("idx_intel_last_seen", "intel_indicator", ["last_seen"])
    op.create_index("idx_intel_type_value", "intel_indicator", ["normalized_type", "normalized_value"])
    op.create_index("idx_intel_pushed", "intel_indicator", ["pushed_to_ta_node"])
    op.create_table(
        "sync_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_name", sa.String(128), unique=True, nullable=False),
        sa.Column("last_timestamp", sa.Text()),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(64)),
        sa.Column("error_message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "app_config",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(128), unique=True, nullable=False),
        sa.Column("value", sa.Text()),
        sa.Column("encrypted", sa.Boolean(), default=False),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade():
    op.drop_table("app_config")
    op.drop_table("sync_state")
    op.drop_table("intel_indicator")

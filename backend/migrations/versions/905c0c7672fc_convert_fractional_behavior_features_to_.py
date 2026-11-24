"""Convert fractional behavior-feature columns to floating-point storage.

Revision ID: 905c0c7672fc
Revises: fe1c1f566143
Create Date: 2026-11-14 01:28:48.615809

"""
from typing import Sequence, Union

from alembic import op
from alembic import context
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '905c0c7672fc'
down_revision: Union[str, None] = 'fe1c1f566143'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if context.is_offline_mode():
        return

    inspector = sa.inspect(op.get_bind())
    if "behavior_features" not in inspector.get_table_names():
        return

    columns = {column["name"]: column for column in inspector.get_columns("behavior_features")}
    fractional_columns = (
        "login_failure_ratio",
        "average_login_hour",
        "process_activity_frequency",
        "download_related_activity_frequency",
        "authentication_to_file_activity_ratio",
        "authentication_to_process_activity_ratio",
        "avg_files_per_session",
    )
    conversions = [
        (name, columns[name]["type"])
        for name in fractional_columns
        if name in columns and not isinstance(columns[name]["type"], sa.Float)
    ]
    if not conversions:
        return

    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("behavior_features", recreate="always") as batch:
            for name, old_type in conversions:
                batch.alter_column(name, existing_type=old_type, type_=sa.Float())
    else:
        for name, old_type in conversions:
            op.alter_column(
                "behavior_features",
                name,
                existing_type=old_type,
                type_=sa.Float(),
            )


def downgrade() -> None:
    raise NotImplementedError("Converting fractional feature values back to integers would lose data.")

"""Extends options for symlinks in cloud sync

Revision ID: 7f948129b46d
Revises: 61095406c3a0
Create Date: 2024-01-27 19:07:26.943266+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7f948129b46d'
down_revision = '61095406c3a0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('tasks_cloudsync', schema=None) as batch_op:
        batch_op.add_column(sa.Column('symlinks', sa.String(20), nullable=True))

    op.execute("UPDATE tasks_cloudsync SET symlinks = 'FOLLOW' WHERE follow_symlinks = 1")
    op.execute("UPDATE tasks_cloudsync SET symlinks = 'IGNORE' WHERE follow_symlinks = 0")

    with op.batch_alter_table('tasks_cloudsync', schema=None) as batch_op:
        batch_op.alter_column('symlinks', existing_type=sa.String(20), nullable=False)
        batch_op.drop_column('follow_symlinks')


def downgrade():
    with op.batch_alter_table('tasks_cloudsync', schema=None) as batch_op:
        batch_op.add_column(sa.Column('follow_symlinks', sa.Boolean(), nullable=True))

    op.execute("UPDATE tasks_cloudsync SET follow_symlinks = 0 WHERE symlinks = 'IGNORE'")
    op.execute("UPDATE tasks_cloudsync SET follow_symlinks = 1 WHERE symlinks <> 'IGNORE'")

    with op.batch_alter_table('tasks_cloudsync', schema=None) as batch_op:
        batch_op.alter_column('follow_symlinks', existing_type=sa.Boolean(), nullable=False)
        batch_op.drop_column('symlinks')
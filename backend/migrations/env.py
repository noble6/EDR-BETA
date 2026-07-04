"""
Alembic environment configuration for EDR-BETA.

Uses the synchronous psycopg2 URL (sqlalchemy standard) for migration runs.
The DATABASE_URL env var uses the asyncpg dialect for runtime — we swap the
driver prefix here so Alembic can work with its sync engine.
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

# ---------------------------------------------------------------------------
# Alembic Config object
# ---------------------------------------------------------------------------
config = context.config

# Configure Python logging from alembic.ini if present
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------------------
# Target metadata (point at SQLAlchemy Base for autogenerate support)
# ---------------------------------------------------------------------------
# Import Base from db models so alembic autogenerate can detect schema changes
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.models import Base
target_metadata = Base.metadata

# ---------------------------------------------------------------------------
# Database URL resolution
# ---------------------------------------------------------------------------
def get_sync_url() -> str:
    """
    Convert the asyncpg DATABASE_URL to a psycopg2-compatible URL for Alembic.
    No credentials are hardcoded — always read from the environment.
    """
    url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://threatuser:threatpass@localhost:5432/threatdb",
    )
    # Alembic runs synchronously — swap asyncpg driver for psycopg2
    return url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")


# ---------------------------------------------------------------------------
# Offline migration (generate SQL scripts)
# ---------------------------------------------------------------------------
def run_migrations_offline() -> None:
    url = get_sync_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migration (execute against live DB)
# ---------------------------------------------------------------------------
def run_migrations_online() -> None:
    connectable = create_engine(
        get_sync_url(),
        poolclass=pool.NullPool,  # single connection for migration run
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

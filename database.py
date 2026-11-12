import os
import tempfile
import logging
from typing import Generator
from sqlalchemy import create_engine, text, inspect, Boolean, Integer
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.pool import StaticPool
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("BloodBackend.Database")

# Requirement 1: Zero Hardcoded URLs. Read strictly from environment variable.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

engine = None
is_sqlite_fallback = False

def create_database_engine():
    """
    Attempts to connect to primary PostgreSQL database with timeout safeguards.
    Gracefully falls back to local persistent SQLite with StaticPool upon any failure.
    """
    global is_sqlite_fallback

    # Normalize URL for SQLAlchemy (postgres:// -> postgresql://)
    pg_url = DATABASE_URL
    if pg_url.startswith("postgres://"):
        pg_url = pg_url.replace("postgres://", "postgresql://", 1)

    # Automatically URL-encode password if it contains an unencoded '@' symbol
    if "://" in pg_url and pg_url.count("@") > 1:
        try:
            import urllib.parse
            prefix, rest = pg_url.split("://", 1)
            userinfo, hostinfo = rest.rsplit("@", 1)
            if ":" in userinfo:
                user, password = userinfo.split(":", 1)
                encoded_password = urllib.parse.quote(password)
                pg_url = f"{prefix}://{user}:{encoded_password}@{hostinfo}"
        except Exception:
            pass

    if pg_url:
        try:
            logger.info("Attempting connection to primary PostgreSQL database...")
            # connect_timeout=3 ensures fast fallback if remote database is unreachable
            test_engine = create_engine(
                pg_url,
                pool_pre_ping=True,
                pool_recycle=300,
                connect_args={"connect_timeout": 3} if "postgresql" in pg_url else {}
            )
            with test_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Primary PostgreSQL database connected successfully.")
            is_sqlite_fallback = False
            return test_engine
        except Exception as exc:
            logger.warning(
                f"Primary PostgreSQL connection failed ({type(exc).__name__}: {exc}). "
                "Activating persistent SQLite fallback with StaticPool."
            )

    # Requirement 2: Resilient persistent SQLite fallback in system temp directory (Workspace stays 100% clean)
    logger.info("Initializing persistent SQLite fallback engine...")
    is_sqlite_fallback = True
    sqlite_path = (os.environ.get("SQLITE_DB_PATH") or os.path.join(tempfile.gettempdir(), "bloodmatch_fallback.db")).replace("\\", "/")
    return create_engine(
        f"sqlite:///{sqlite_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )

engine = create_database_engine()

# Clean Session Factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base for ORM Models
Base = declarative_base()

# Requirement 4: Clean Session Lifecycle Dependency
def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides an isolated database session.
    Commits on successful completion, rolls back on any exception, and strictly closes.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

# Requirement 3: Auto-Schema Migration & Seeding with try/except safeguards
def init_db():
    """
    Auto-checks and creates all missing tables on startup.
    Seeds standard ABO/Rh blood groups if inventory table is newly created.
    """
    try:
        # Ensure all models are registered in Base.metadata
        import models

        logger.info(f"Running auto-schema migration on {'SQLite Fallback' if is_sqlite_fallback else 'PostgreSQL'}...")
        # Automatically creates tables from metadata
        Base.metadata.create_all(bind=engine)

        # Requirement 3: Auto-detect and safely add any missing columns to existing tables
        inspector = inspect(engine)
        for table_name, table in Base.metadata.tables.items():
            if inspector.has_table(table_name):
                existing_cols = {col['name'] for col in inspector.get_columns(table_name)}
                for col in table.columns:
                    if col.name not in existing_cols:
                        logger.info(f"Auto-migrating missing column: {table_name}.{col.name}")
                        try:
                            if is_sqlite_fallback:
                                col_type = str(col.type.compile(engine.dialect)).replace("NOT NULL", "").strip()
                                default_clause = "DEFAULT 0" if isinstance(col.type, (Boolean, Integer)) else "DEFAULT NULL"
                                with engine.begin() as conn:
                                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type} {default_clause}"))
                            else:
                                col_type = col.type.compile(engine.dialect)
                                with engine.begin() as conn:
                                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type}"))
                        except Exception as col_err:
                            logger.warning(f"Could not auto-add column {table_name}.{col.name}: {col_err}")

        logger.info("Auto-schema migration completed successfully.")

        # Seed initial blood inventory if empty with strictly 0 units (Pristine fresh operational start)
        with SessionLocal() as session:
            count = session.query(models.InventoryModel).count()
            if count == 0:
                logger.info("Initializing 8 clinical ABO & RhD blood groups at 0 units...")
                seeds = [
                    models.InventoryModel(blood_type="O-", units_available=0, status="critical", temperature_celsius=4.0),
                    models.InventoryModel(blood_type="O+", units_available=0, status="critical", temperature_celsius=4.0),
                    models.InventoryModel(blood_type="A-", units_available=0, status="critical", temperature_celsius=4.0),
                    models.InventoryModel(blood_type="A+", units_available=0, status="critical", temperature_celsius=4.0),
                    models.InventoryModel(blood_type="B-", units_available=0, status="critical", temperature_celsius=4.0),
                    models.InventoryModel(blood_type="B+", units_available=0, status="critical", temperature_celsius=4.0),
                    models.InventoryModel(blood_type="AB-", units_available=0, status="critical", temperature_celsius=4.0),
                    models.InventoryModel(blood_type="AB+", units_available=0, status="critical", temperature_celsius=4.0),
                ]
                session.add_all(seeds)
                session.commit()
                logger.info("Default 0-unit inventory initialized successfully.")
    except Exception as exc:
        logger.error(f"Auto-schema migration warning: {exc}")

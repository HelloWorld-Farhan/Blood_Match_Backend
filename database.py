import os
import logging
from typing import Generator
from sqlalchemy import create_engine, text
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

    # Requirement 2: Resilient persistent SQLite fallback with StaticPool
    logger.info("Initializing persistent SQLite fallback engine (bloodmatch_fallback.db)...")
    is_sqlite_fallback = True
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sqlite_path = os.path.join(base_dir, "bloodmatch_fallback.db").replace("\\", "/")
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
        logger.info(f"Running auto-schema migration on {'SQLite Fallback' if is_sqlite_fallback else 'PostgreSQL'}...")
        # Automatically creates tables from metadata
        Base.metadata.create_all(bind=engine)
        logger.info("Auto-schema migration completed successfully.")

        # Seed initial blood inventory if empty
        with SessionLocal() as session:
            from models import InventoryModel
            count = session.query(InventoryModel).count()
            if count == 0:
                logger.info("Seeding initial ABO & RhD clinical inventory units...")
                seeds = [
                    InventoryModel(blood_type="O-", units_available=14, status="optimal", temperature_celsius=3.8),
                    InventoryModel(blood_type="O+", units_available=22, status="optimal", temperature_celsius=4.0),
                    InventoryModel(blood_type="A-", units_available=8, status="moderate", temperature_celsius=3.9),
                    InventoryModel(blood_type="A+", units_available=19, status="optimal", temperature_celsius=4.1),
                    InventoryModel(blood_type="B-", units_available=4, status="critical", temperature_celsius=4.0),
                    InventoryModel(blood_type="B+", units_available=17, status="optimal", temperature_celsius=3.7),
                    InventoryModel(blood_type="AB-", units_available=2, status="critical", temperature_celsius=4.2),
                    InventoryModel(blood_type="AB+", units_available=9, status="moderate", temperature_celsius=4.0),
                ]
                session.add_all(seeds)
                session.commit()
                logger.info("Default inventory seeded successfully.")
    except Exception as exc:
        logger.error(f"Auto-schema migration warning: {exc}")

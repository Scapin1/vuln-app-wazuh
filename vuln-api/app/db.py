# app/db.py
import os
import time
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")  # ej: postgresql://user:pass@host:5432/db

MAX_RETRIES = 10
RETRY_DELAY = 3  # segundos


def _create_engine_with_retry():
    """Crea el engine de SQLAlchemy con reintentos para esperar a que la DB esté lista."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            eng = create_engine(DATABASE_URL, pool_pre_ping=True)
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Conexión a la base de datos establecida.")
            return eng
        except Exception as e:
            if attempt == MAX_RETRIES:
                raise RuntimeError(
                    f"No se pudo conectar a la DB después de {MAX_RETRIES} intentos: {e}"
                )
            logger.warning(
                f"DB no disponible (intento {attempt}/{MAX_RETRIES}). "
                f"Reintentando en {RETRY_DELAY}s..."
            )
            time.sleep(RETRY_DELAY)


engine = _create_engine_with_retry()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

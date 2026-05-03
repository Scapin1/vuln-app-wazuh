# database.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
import os

# Cargamos la URL desde el entorno
DATABASE_URL = os.getenv("DATABASE_URL")

# Creamos el motor asíncrono
engine = create_async_engine(DATABASE_URL, echo=True)

# Generador de sesiones para las rutas de FastAPI
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

# Dependencia para usar en los endpoints
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
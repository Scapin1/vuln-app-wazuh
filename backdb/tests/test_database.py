# test_database.py

import pytest
from unittest.mock import AsyncMock, patch
from database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.mark.asyncio
async def test_get_db_yields_session():
    """Verifica que get_db entregue una sesión y maneje el ciclo de vida"""
    
    # Creamos el mock de la sesión
    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.__aenter__.return_value = mock_session
    
    # IMPORTANTE: Parcheamos donde se USA, que es dentro de database.py
    with patch("database.AsyncSessionLocal", return_value=mock_session):
        from database import get_db
        
        # Usamos el generador de forma natural
        db_gen = get_db()
        session = await db_gen.__anext__()
        
        assert session == mock_session
        
        # Cerramos el generador para disparar el __aexit__
        try:
            await db_gen.__anext__()
        except StopAsyncIteration:
            pass
            
    assert mock_session.__aexit__.called

def test_base_exists():
    """Verifica que el objeto Base de SQLAlchemy sea válido"""
    from database import Base
    # En lugar de issubclass, verificamos que tenga metadata (propio de SQLAlchemy)
    assert hasattr(Base, "metadata")
    assert Base is not None
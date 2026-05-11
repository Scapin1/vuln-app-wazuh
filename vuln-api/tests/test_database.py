# tests/test_database.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import Base, get_db

@pytest.mark.asyncio
async def test_get_db_yields_session():
    """Verifica que el generador get_db entregue una sesión y la cierre al terminar"""
    
    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.__aenter__.return_value = mock_session
    
    with patch("app.db.AsyncSessionLocal", return_value=mock_session):
        from app.db import get_db
        
        db_gen = get_db()
        session = await db_gen.__anext__()
        
        assert session == mock_session

        try:
            await db_gen.__anext__()
        except StopAsyncIteration:
            pass
            

        assert mock_session.__aexit__.called

def test_base_exists():
    from app.db import Base
    """Verifica que el objeto Base de SQLAlchemy esté correctamente definido"""
    assert hasattr(Base, "metadata")
    assert Base is not None
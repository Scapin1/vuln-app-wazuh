# tests/test_database.py
import os
import sys
os.environ["DATABASE_URL"] = "postgresql+asyncpg://user:pass@localhost/testdb"
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db, Base


@pytest.mark.asyncio
async def test_get_db_yields_session():
    """Verifica que el generador get_db entregue una sesión y la cierre al terminar"""
    
    mock_session = AsyncMock(spec=AsyncSession)
    
    with patch("app.db.AsyncSessionLocal") as mock_session_factory:
        mock_session_factory.return_value.__aenter__.return_value = mock_session
        
        generator = get_db()
        db_yielded = await anext(generator)
        
        assert db_yielded == mock_session

        try:
            await anext(generator)
        except StopAsyncIteration:
            pass
            

        mock_session.close.assert_awaited_once()

def test_base_exists():
    """Verifica que el objeto Base de SQLAlchemy esté correctamente definido"""
    assert Base is not None
    assert hasattr(Base, "metadata")
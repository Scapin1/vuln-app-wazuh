# tests/conftest.py
import os
import pytest
os.environ["DATABASE_URL"] = "postgresql+asyncpg://user:pass@localhost/testdb"

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"
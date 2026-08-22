# tests/routers/test_analytics.py — cubre app/routers/analytics.py
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException as FastAPIException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import Column, DateTime
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, hash_password
from app.db import get_db
from app.main import app
from app.models import User, VulnStatus
from app.routers.analytics import get_date_filters

REAL_HASH = hash_password("old_password")

mock_user = User(
    user_name="Admin Test",
    user_password=REAL_HASH,
    user_status=True,
    user_delete=False
)
mock_user.user_id = 1


def mock_refresh_side_effect(obj):
    if hasattr(obj, 'user_id') and getattr(obj, 'user_id', None) is None:
        obj.user_id = 1
    elif hasattr(obj, 'id') and getattr(obj, 'id', None) is None:
        obj.id = uuid.uuid4()
    if hasattr(obj, 'timestamp') and getattr(obj, 'timestamp', None) is None:
        obj.timestamp = datetime.now(timezone.utc)
    if hasattr(obj, 'cve_id') and getattr(obj, 'cve_id', None) is None:
        obj.cve_id = "CVE-2026-MOCK"

async def override_get_db():
    db = AsyncMock(add=MagicMock())

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_result.scalars.return_value.first.return_value = None
    mock_result.scalar_one_or_none.return_value = mock_user

    db.execute.return_value = mock_result
    db.refresh.side_effect = mock_refresh_side_effect
    yield db


@pytest.fixture(autouse=True)
def baseline_overrides():
    saved = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: mock_user
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved)


def make_client(mock_db):
    app.dependency_overrides[get_db] = lambda: mock_db
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@asynccontextmanager
async def no_root_path():
    original = app.root_path
    app.root_path = ""
    try:
        yield
    finally:
        app.root_path = original


class MockResult:
    def __init__(self, data_scalar=None, data_all=None, data_first=None, data_one_or_none=None):
        self._scalar = data_scalar
        self._all = data_all
        self._first = data_first
        self._one_or_none = data_one_or_none

    def scalar(self):
        return self._scalar

    def scalar_one_or_none(self):
        return self._one_or_none or self._scalar

    def scalars(self):
        return self

    def all(self):
        return self._all or []

    def first(self):
        return self._first










@pytest.mark.asyncio
async def test_get_vulns_events_not_found():
    mock_db = AsyncMock()
    mock_db.execute.side_effect = [
        MockResult(data_scalar=None)
    ]
    app.dependency_overrides[get_db] = lambda: mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(
            "/vulns/events",
            params={"connection_id": 999, "start_ms": 1000, "end_ms": 2000}
        )

    assert response.status_code == 404


@pytest.mark.anyio
async def test_get_vulns_timeline_gantt_success():
    """
    Verifica que el endpoint del diagrama de Gantt retorne la estructura
    correcta realizando un mock de las 4 consultas secuenciales de SQLAlchemy.
    """
    # 1. Preparar las fechas de prueba
    mock_now = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)

    # 2. Configurar los resultados simulados (Mocks) para cada query

    # Query 1: res_bounds (min_ts, max_ts)
    mock_result_bounds = MagicMock()
    mock_result_bounds.one_or_none.return_value = (mock_now, mock_now)

    # Query 2: total_cves (count)
    mock_result_count = MagicMock()
    mock_result_count.scalar.return_value = 1

    # Query 3: page_cves (cve_id, severity, description)
    mock_result_page = MagicMock()
    mock_result_page.all.return_value = [
        ("CVE-2024-1234", "CRITICAL", "Descripción de prueba para el CVE")
    ]

    # Query 4: all_snapshots (cve_id, timestamp, hostname, status)
    mock_result_snaps = MagicMock()
    # Retornamos el estado como string ya que tu código soporta (hasattr(st, 'value') else str(st))
    mock_result_snaps.all.return_value = [
        ("CVE-2024-1234", mock_now, "agent-test-01", "Detected")
    ]

    # 3. Crear el mock de la sesión de base de datos
    mock_session = AsyncMock()
    # side_effect devolverá los resultados en el orden en que se llama a 'await db.execute()'
    mock_session.execute.side_effect = [
        mock_result_bounds,
        mock_result_count,
        mock_result_page,
        mock_result_snaps
    ]

    # 4. Sobrescribir la dependencia get_db en FastAPI
    app.dependency_overrides[get_db] = lambda: mock_session

    # 5. Ejecutar la petición HTTP usando ASGITransport
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""

    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/vulns/timeline/gantt",
                params={
                    "connection_id": 1,
                    "period": "30d"
                }
            )
    finally:

    # 6. Limpiar el override para no afectar otros tests
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    # 7. Aserciones (Verificar el comportamiento)
    assert response.status_code == 200

    data = response.json()

    # Validar la paginación y metadata
    assert data["total_cves"] == 1
    assert data["total_pages"] == 1
    assert data["current_page"] == 1
    assert data["min_timestamp"] == mock_now.isoformat()
    assert data["max_timestamp"] == mock_now.isoformat()

    # Validar la estructura del CVE
    assert len(data["cves"]) == 1
    cve_data = data["cves"][0]
    assert cve_data["cve_id"] == "CVE-2024-1234"
    assert cve_data["severity"] == "CRITICAL"
    assert cve_data["is_resolved"] is False  # Falso porque el snapshot es "Detected"

    # Validar el snapshot generado
    assert len(cve_data["snapshots"]) == 1
    snapshot = cve_data["snapshots"][0]
    assert snapshot["agent_count"] == 1
    assert "agent-test-01" in snapshot["agents"]

@pytest.mark.anyio
async def test_get_vulns_timeline_gantt_with_filters():
    """
    Verifica que el endpoint procese correctamente los parámetros opcionales
    agent, severity y search para alcanzar cobertura en esas ramas (if).
    """
    mock_now = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)

    mock_result_bounds = MagicMock()
    mock_result_bounds.one_or_none.return_value = (mock_now, mock_now)

    mock_result_count = MagicMock()
    mock_result_count.scalar.return_value = 1

    mock_result_page = MagicMock()
    mock_result_page.all.return_value = [("CVE-2024-1234", "CRITICAL", "Desc")]

    mock_result_snaps = MagicMock()
    mock_result_snaps.all.return_value = [("CVE-2024-1234", mock_now, "agent-01", "Detected")]

    mock_session = AsyncMock()
    mock_session.execute.side_effect = [
        mock_result_bounds,
        mock_result_count,
        mock_result_page,
        mock_result_snaps
    ]

    app.dependency_overrides[get_db] = lambda: mock_session
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""

    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/vulns/timeline/gantt",
                params={
                    "connection_id": 1,
                    "agent": "ubuntu",          # Activa 'if agent:'
                    "severity": "CRITICAL",     # Activa 'if severity:'
                    "search": "CVE-2024"        # Activa 'if search:'
                }
            )
    finally:
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    assert response.status_code == 200


@pytest.mark.anyio
async def test_get_vulns_timeline_gantt_empty_results():
    """
    Verifica el comportamiento cuando no hay vulnerabilidades detectadas,
    cubriendo el escenario donde 'page_cves' está vacío.
    """
    # Query 1: res_bounds (Sin fechas registradas)
    mock_result_bounds = MagicMock()
    mock_result_bounds.one_or_none.return_value = (None, None)

    # Query 2: total_cves (Cero CVEs)
    mock_result_count = MagicMock()
    mock_result_count.scalar.return_value = 0

    # Query 3: page_cves (Lista vacía)
    mock_result_page = MagicMock()
    mock_result_page.all.return_value = []

    # Mock DB: Solo pasamos 3 resultados porque la consulta de snapshots no se ejecutará
    mock_session = AsyncMock()
    mock_session.execute.side_effect = [
        mock_result_bounds,
        mock_result_count,
        mock_result_page
    ]

    app.dependency_overrides[get_db] = lambda: mock_session
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""

    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/vulns/timeline/gantt",
                params={"connection_id": 1}
            )
    finally:
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    assert response.status_code == 200
    data = response.json()

    # Validaciones del escenario vacío
    assert data["total_cves"] == 0
    assert data["total_pages"] == 0
    assert len(data["cves"]) == 0
    assert data["min_timestamp"] is None
    assert data["max_timestamp"] is None


@pytest.mark.anyio
async def test_get_vulns_analytics_summary_success():
    """
    Verifica que el endpoint de analíticas retorne las distribuciones correctas,
    simulando las 4 consultas secuenciales (Severity, Status, Top Agents, Top CVE).
    """
    # 1. Configurar los resultados simulados (Mocks) para cada query

    # Query 1: res_severity (severity, count)
    mock_result_severity = MagicMock()
    mock_result_severity.all.return_value = [
        ("CRITICAL", 5),
        ("HIGH", 2),
        ("LOW", 1)
    ]

    # Query 2: res_status (status, count)
    mock_result_status = MagicMock()
    # Usamos string para el estado, compatible con tu lógica hasattr(row[0], 'value')
    mock_result_status.all.return_value = [
        ("Detected", 4),
        ("Resolved", 3),
        ("Re-emerged", 1)
    ]

    # Query 3: res_top_agents (hostname, count)
    mock_result_top_agents = MagicMock()
    mock_result_top_agents.all.return_value = [
        ("server-prod-01", 4),
        ("desktop-dev-02", 2)
    ]

    # Query 4: res_top_cve (cve_id, count) - Solo se llama si critical_count > 0
    mock_result_top_cve = MagicMock()
    # Atento aquí: tu código usa .first() en esta query, no .all()
    mock_result_top_cve.first.return_value = ("CVE-2024-9999", 5)

    # 2. Crear el mock de la sesión de base de datos
    mock_session = AsyncMock()
    mock_session.execute.side_effect = [
        mock_result_severity,
        mock_result_status,
        mock_result_top_agents,
        mock_result_top_cve
    ]

    # 3. Sobrescribir la dependencia get_db en FastAPI
    app.dependency_overrides[get_db] = lambda: mock_session

    # 4. Ejecutar la petición HTTP evitando el problema del root_path (404)
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""

    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/vulns/analytics",
                params={
                    "connection_id": 1,
                    "period": "30d"
                }
            )
    finally:
        # 5. Limpiar overrides y restaurar estado
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    # 6. Aserciones (Verificar el comportamiento)
    assert response.status_code == 200

    data = response.json()

    # Validar distribución de severidad
    assert data["severity_distribution"]["CRITICAL"] == 5
    assert data["severity_distribution"]["HIGH"] == 2
    assert data["severity_distribution"]["MEDIUM"] == 0 # No enviado en el mock, debe ser 0
    assert data["critical_count"] == 5

    # Validar distribución de estados
    # Ojo: Tu código mapea "Detected" a "Activo", "Resolved" a "Resuelto", etc.
    assert data["status_distribution"]["Activo"] == 4
    assert data["status_distribution"]["Resuelto"] == 3
    assert data["status_distribution"]["Reabierto"] == 1

    # Validar top agents
    assert len(data["top_agents"]) == 2
    assert data["top_agents"][0]["agent"] == "server-prod-01"
    assert data["top_agents"][0]["count"] == 4

    # Validar Top CVE Crítico
    assert data["top_critical_cve"] == "CVE-2024-9999"

def test_get_date_filters_valid_periods():
    """
    Verifica que los periodos predefinidos devuelvan la cantidad
    correcta de filtros usando una columna real de SQLAlchemy.
    """
    # Usamos una columna ficticia de SQLAlchemy en vez de MagicMock
    mock_col = Column('timestamp', DateTime)

    assert len(get_date_filters("24h", None, mock_col)) == 1
    assert len(get_date_filters("7d", None, mock_col)) == 1
    assert len(get_date_filters("30d", None, mock_col)) == 1
    assert len(get_date_filters("all", None, mock_col)) == 0


def test_get_date_filters_day_valid():
    """
    Verifica el periodo 'day' cuando se pasa una fecha correcta.
    """
    mock_col = Column('timestamp', DateTime)
    filters = get_date_filters("day", "2026-07-13", mock_col)

    assert len(filters) == 2


def test_get_date_filters_day_missing_date():
    """
    Verifica que arroje error 400 si se pide 'day' pero no se envía la fecha.
    """
    mock_col = Column('timestamp', DateTime)

    # Usamos el alias FastAPIException para garantizar que atrapamos la correcta
    with pytest.raises(FastAPIException) as exc_info:
        get_date_filters("day", None, mock_col)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "Falta parámetro date"


def test_get_date_filters_day_invalid_date():
    """
    Verifica que arroje error 400 si se pide 'day' con un formato de fecha incorrecto.
    """
    mock_col = Column('timestamp', DateTime)

    with pytest.raises(FastAPIException) as exc_info:
        get_date_filters("day", "13-07-2026", mock_col)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "Formato de fecha inválido"


def test_get_date_filters_invalid_period():
    """
    Verifica que arroje error 400 si se pasa un periodo que no existe.
    """
    mock_col = Column('timestamp', DateTime)

    with pytest.raises(FastAPIException) as exc_info:
        get_date_filters("48h", None, mock_col)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "Periodo no válido"

@pytest.mark.anyio
async def test_get_vulns_dashboard_success():
    """
    Verifica que el endpoint del dashboard retorne las distribuciones
    correctas de severidad y estado haciendo un mock de las 2 consultas.
    """
    # 1. Configurar Mocks para las 2 queries

    # Query 1: res_sev (severity, count)
    mock_result_sev = MagicMock()
    # Incluimos una severidad "UNKNOWN" para verificar que el código
    # la ignora correctamente sin fallar (gracias al 'if sev in severity_distribution')
    mock_result_sev.all.return_value = [
        ("CRITICAL", 10),
        ("HIGH", 5),
        ("UNKNOWN", 2)
    ]

    # Query 2: res_status (status, count)
    mock_result_status = MagicMock()
    mock_result_status.all.return_value = [
        ("Detected", 8),
        ("Resolved", 7)
    ]

    # 2. Mock de la sesión de base de datos
    mock_session = AsyncMock()
    mock_session.execute.side_effect = [
        mock_result_sev,
        mock_result_status
    ]

    # 3. Inyectar dependencias y manejar el root_path
    app.dependency_overrides[get_db] = lambda: mock_session
    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""

    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                "/vulns/dashboard",
                params={
                    "connection_id": 1,
                    "period": "7d"
                }
            )
    finally:
        # 4. Limpiar overrides
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    # 5. Aserciones
    assert response.status_code == 200

    data = response.json()

    # Validar distribución de severidad
    assert data["severity_distribution"]["CRITICAL"] == 10
    assert data["severity_distribution"]["HIGH"] == 5
    assert data["severity_distribution"]["MEDIUM"] == 0 # Sin datos, debe ser 0
    assert data["severity_distribution"]["LOW"] == 0    # Sin datos, debe ser 0
    # "UNKNOWN" no debe estar en la respuesta final
    assert "UNKNOWN" not in data["severity_distribution"]

    # Validar distribución de estado
    assert data["status_distribution"]["Detected"] == 8
    assert data["status_distribution"]["Resolved"] == 7
    assert data["status_distribution"]["Re-emerged"] == 0 # Sin datos, debe ser 0

    # Validar suma total de los estados reportados
    assert data["total"] == 15

@pytest.mark.anyio
async def test_get_critical_vulnerabilities_view_success():
    """
    Verifica que el endpoint de la vista materializada procese correctamente
    los resultados de la query cruda simulando diccionarios.
    """
    # 1. Configurar el Mock de la Base de Datos para mappings().all()
    mock_result = MagicMock()
    mock_result.mappings().all.return_value = [
        {
            "cve_id": "CVE-2024-0001",
            "cvss_score": "9.8",  # En BD esto suele venir como String, Decimal o Numeric
            "description": "Ejemplo de vulnerabilidad crítica",
            "total_affected_agents": 2,
            "affected_wazuh_agent_ids": ["001", "002"],
            "affected_hostnames": ["server-prod-1", "server-prod-2"]
        },
        {
            "cve_id": "CVE-2024-0002",
            "cvss_score": None,   # Caso de prueba: score nulo
            "description": "Otra vulnerabilidad",
            "total_affected_agents": 1,
            "affected_wazuh_agent_ids": ["003"],
            "affected_hostnames": ["desktop-01"]
        }
    ]

    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result

    # 2. Configurar el Mock del Usuario Autenticado
    mock_user = User(user_name="Admin Test")

    # 3. Sobrescribir las dependencias
    app.dependency_overrides[get_db] = lambda: mock_session
    app.dependency_overrides[get_current_user] = lambda: mock_user

    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""

    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/vulns/analytics/critical-view")
    finally:
        # Limpiar dependencias
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    # 4. Aserciones
    assert response.status_code == 200
    data = response.json()

    # Validamos que devuelva 2 registros
    assert len(data) == 2

    # Validar el primer registro (Conversión a Float y listas)
    assert data[0]["cve_id"] == "CVE-2024-0001"
    assert data[0]["cvss_score"] == 9.8  # El test confirma que parseó el "9.8" a float 9.8
    assert data[0]["total_affected_agents"] == 2
    assert "server-prod-1" in data[0]["affected_hostnames"]

    # Validar el segundo registro (manejo de nulos)
    assert data[1]["cve_id"] == "CVE-2024-0002"
    assert data[1]["cvss_score"] is None


@pytest.mark.anyio
async def test_get_critical_vulnerabilities_view_empty():
    """
    Verifica que el endpoint devuelva una lista vacía si la vista materializada
    no tiene registros.
    """
    mock_result = MagicMock()
    mock_result.mappings().all.return_value = []

    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result

    mock_user = User()

    app.dependency_overrides[get_db] = lambda: mock_session
    app.dependency_overrides[get_current_user] = lambda: mock_user

    transport = ASGITransport(app=app)
    original_root_path = app.root_path
    app.root_path = ""

    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/vulns/analytics/critical-view")
    finally:
        app.dependency_overrides.clear()
        app.root_path = original_root_path

    assert response.status_code == 200
    data = response.json()

    # Validar que responde correctamente con un array vacío
    assert isinstance(data, list)
    assert len(data) == 0


@pytest.mark.asyncio
async def test_get_vulns_filter_options_success():
    """Cubre GET /vulns/filter-options filtrando filas con hostname/cve nulos"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_agents = MagicMock()
    res_agents.all.return_value = [("agent-a", 5), (None, 3)]

    res_cves = MagicMock()
    res_cves.all.return_value = [("CVE-2024-0001", 4), (None, 2)]

    mock_db.execute.side_effect = [res_agents, res_cves]

    async with make_client(mock_db) as ac, no_root_path():
        response = await ac.get("/vulns/filter-options", params={"connection_id": 1})

    assert response.status_code == 200
    body = response.json()
    assert body["agents"] == [{"name": "agent-a", "count": 5}]
    assert body["cves"] == [{"id": "CVE-2024-0001", "count": 4}]


@pytest.mark.asyncio
async def test_get_vulns_events_success():
    """Cubre GET /vulns/events separando detections/resolutions (incluye Re-emerged y hostname nulo)"""
    now = datetime.now(timezone.utc)
    mock_db = AsyncMock(spec=AsyncSession)

    res_conn = MagicMock()
    res_conn.scalar.return_value = 1

    res_rows = MagicMock()
    res_rows.all.return_value = [
        ("CVE-1", now, "agent-1", VulnStatus.Detected),
        ("CVE-2", now, None, VulnStatus.Resolved),
        ("CVE-3", now, "agent-3", "Re-emerged"),
    ]

    mock_db.execute.side_effect = [res_conn, res_rows]

    async with make_client(mock_db) as ac, no_root_path():
        response = await ac.get(
            "/vulns/events",
            params={"connection_id": 1, "start_ms": 1000, "end_ms": int(now.timestamp() * 1000)},
        )

    assert response.status_code == 200
    body = response.json()
    assert [e["cve_id"] for e in body["detections"]] == ["CVE-1", "CVE-3"]
    assert body["resolutions"][0]["cve_id"] == "CVE-2"
    assert body["resolutions"][0]["agent"] == "Desconocido"


@pytest.mark.asyncio
async def test_get_vulns_events_connection_not_found():
    """Cubre el 404 cuando la conexión no existe en events"""
    mock_db = AsyncMock(spec=AsyncSession)

    res_conn = MagicMock()
    res_conn.scalar.return_value = None
    mock_db.execute.side_effect = [res_conn]

    async with make_client(mock_db) as ac, no_root_path():
        response = await ac.get(
            "/vulns/events",
            params={"connection_id": 999, "start_ms": 1000, "end_ms": 2000},
        )

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "Conexión no encontrada"


@pytest.mark.asyncio
async def test_refresh_critical_view_success():
    """Cubre POST /vulns/analytics/refresh-critical (flujo exitoso)"""
    mock_db = AsyncMock(spec=AsyncSession)

    async with make_client(mock_db) as ac, no_root_path():
        response = await ac.post("/vulns/analytics/refresh-critical")

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert mock_db.commit.called


@pytest.mark.asyncio
async def test_refresh_critical_view_error_500():
    """Cubre el bloque except de refresh-critical (rollback + 500)"""
    mock_db = AsyncMock(spec=AsyncSession)
    mock_db.execute.side_effect = Exception("fallo de BD")

    async with make_client(mock_db) as ac, no_root_path():
        response = await ac.post("/vulns/analytics/refresh-critical")

    assert response.status_code == 500
    assert "Error interno" in response.json()["detail"]
    assert mock_db.rollback.called

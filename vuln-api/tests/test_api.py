import pytest
from unittest.mock import patch, MagicMock
from app.models import Manager, Asset, VulnerabilityCatalog, VulnerabilityDetection
from app.crypto import encrypt


# --- Helpers ---

MOCK_VULN_PAYLOAD = [
    {
        "agent": {"id": "001", "name": "agent-1", "ip": "192.168.1.10"},
        "host": {"os": {"full": "Ubuntu 22.04", "platform": "ubuntu", "version": "22.04"}},
        "package": {"name": "openssl", "version": "1.1.1", "type": "deb", "architecture": "amd64"},
        "vulnerability": {
            "id": "CVE-2023-0001",
            "severity": "High",
            "score": {"base": 7.5, "version": "3.1"},
            "detected_at": None,
            "published_at": None,
            "description": "Test vulnerability",
            "reference": "https://nvd.nist.gov",
            "scanner": {"vendor": "wazuh"},
        },
    }
]


def _create_manager(db, name="test-manager"):
    manager = Manager(
        nombre=name,
        api_url="https://wazuh.local:9200",
        wazuh_user="admin",
        wazuh_password=encrypt("secret"),
    )
    db.add(manager)
    db.commit()
    db.refresh(manager)
    return manager


# --- Health Check ---

def test_status_endpoint(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "service" in data


# --- Sync Endpoint ---

def test_sync_endpoint_returns_202(client):
    res = client.post("/api/sync")
    assert res.status_code == 200
    assert "Sincronización" in res.json()["message"]


# --- Sync Logic ---

@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN_PAYLOAD)
def test_sync_manager_creates_assets(mock_fetch, db_session):
    from app.main import sync_manager

    manager = _create_manager(db_session)
    count = sync_manager(db_session, manager)

    assert count == 1
    assets = db_session.query(Asset).all()
    assert len(assets) == 1
    assert assets[0].wazuh_agent_id == "001"
    assert assets[0].hostname == "agent-1"


@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN_PAYLOAD)
def test_sync_manager_creates_catalog_entry(mock_fetch, db_session):
    from app.main import sync_manager

    manager = _create_manager(db_session)
    sync_manager(db_session, manager)

    cve = db_session.query(VulnerabilityCatalog).filter_by(cve_id="CVE-2023-0001").first()
    assert cve is not None
    assert cve.description == "Test vulnerability"
    assert float(cve.cvss_score) == 7.5


@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN_PAYLOAD)
def test_sync_manager_creates_detection(mock_fetch, db_session):
    from app.main import sync_manager

    manager = _create_manager(db_session)
    sync_manager(db_session, manager)

    detections = db_session.query(VulnerabilityDetection).all()
    assert len(detections) == 1
    assert detections[0].cve_id == "CVE-2023-0001"
    assert detections[0].package_name == "openssl"


@patch("app.main.fetch_all_vulns", return_value=[])
def test_sync_manager_empty_payload(mock_fetch, db_session):
    from app.main import sync_manager

    manager = _create_manager(db_session)
    result = sync_manager(db_session, manager)

    assert result == 0
    assert db_session.query(Asset).count() == 0
    assert db_session.query(VulnerabilityCatalog).count() == 0


@patch("app.main.fetch_all_vulns")
def test_sync_manager_skips_vuln_without_cve(mock_fetch, db_session):
    from app.main import sync_manager

    mock_fetch.return_value = [{
        "agent": {"id": "001", "name": "host-1"},
        "host": {"os": {}},
        "package": {"name": "curl", "version": "7.81"},
        "vulnerability": {"id": None, "severity": "High", "score": {}},
    }]
    manager = _create_manager(db_session)
    result = sync_manager(db_session, manager)

    assert result == 0
    assert db_session.query(VulnerabilityCatalog).count() == 0


@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN_PAYLOAD)
def test_sync_manager_idempotent_assets(mock_fetch, db_session):
    """Sincronizar dos veces no debe duplicar assets"""
    from app.main import sync_manager

    manager = _create_manager(db_session)
    sync_manager(db_session, manager)
    sync_manager(db_session, manager)

    assert db_session.query(Asset).count() == 1


@patch("app.main.fetch_all_vulns")
def test_sync_manager_multiple_agents(mock_fetch, db_session):
    from app.main import sync_manager

    mock_fetch.return_value = [
        {
            "agent": {"id": "001", "name": "agent-1", "ip": "10.0.0.1"},
            "host": {"os": {"version": "22.04"}},
            "package": {"name": "curl", "version": "7.81"},
            "vulnerability": {"id": "CVE-2023-0001", "severity": "High", "score": {"base": 7.5}},
        },
        {
            "agent": {"id": "002", "name": "agent-2", "ip": "10.0.0.2"},
            "host": {"os": {"version": "20.04"}},
            "package": {"name": "nginx", "version": "1.18"},
            "vulnerability": {"id": "CVE-2023-0002", "severity": "Medium", "score": {"base": 5.0}},
        },
    ]
    manager = _create_manager(db_session)
    count = sync_manager(db_session, manager)

    assert count == 2
    assert db_session.query(Asset).count() == 2
    assert db_session.query(VulnerabilityCatalog).count() == 2
    assert db_session.query(VulnerabilityDetection).count() == 2
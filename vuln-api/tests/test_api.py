import pytest
from unittest.mock import patch, MagicMock
from app.models import Manager, Asset, VulnerabilityCatalog, VulnerabilityDetection, SeverityEnum
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

@patch("app.main.run_sync_job")
def test_sync_endpoint_returns_200(mock_job, client):
    res = client.post("/api/sync")
    assert res.status_code == 200
    assert "Sincronización" in res.json()["message"]


# --- Parser Unit Tests ---

def test_parse_severity_known():
    from app.main import _parse_severity
    assert _parse_severity({"severity": "High"}) == SeverityEnum.High
    assert _parse_severity({"severity": "critical"}) == SeverityEnum.Critical
    assert _parse_severity({"severity": "medium"}) == SeverityEnum.Medium
    assert _parse_severity({"severity": "low"}) == SeverityEnum.Low


def test_parse_severity_unknown_defaults_to_untriaged():
    from app.main import _parse_severity
    assert _parse_severity({"severity": "Unknown"}) == SeverityEnum.Untriaged
    assert _parse_severity({}) == SeverityEnum.Untriaged


def test_parse_score_valid():
    from app.main import _parse_score
    assert _parse_score({"score": {"base": 7.5}}) == 7.5
    assert _parse_score({"score": {"base": "9.8"}}) == 9.8


def test_parse_score_invalid():
    from app.main import _parse_score
    assert _parse_score({"score": {"base": "not-a-number"}}) is None
    assert _parse_score({"score": {}}) is None
    assert _parse_score({}) is None
    assert _parse_score({"score": None}) is None


def test_parse_raw_vulns_skips_no_cve():
    from app.main import _parse_raw_vulns
    raw = [{"agent": {"id": "001"}, "host": {}, "package": {}, "vulnerability": {"id": None}}]
    assets, catalog, detections = _parse_raw_vulns(raw, "manager-uuid")
    assert len(assets) == 0
    assert len(catalog) == 0
    assert len(detections) == 0


def test_parse_raw_vulns_deduplicates_agents():
    from app.main import _parse_raw_vulns
    raw = [
        {
            "agent": {"id": "001", "name": "host-1"},
            "host": {"os": {"version": "22.04"}},
            "package": {"name": "curl", "version": "7.81"},
            "vulnerability": {"id": "CVE-A", "severity": "High", "score": {"base": 5.0}},
        },
        {
            "agent": {"id": "001", "name": "host-1"},
            "host": {"os": {"version": "22.04"}},
            "package": {"name": "wget", "version": "1.0"},
            "vulnerability": {"id": "CVE-B", "severity": "Low", "score": {"base": 2.0}},
        },
    ]
    assets, catalog, detections = _parse_raw_vulns(raw, "mgr-id")
    assert len(assets) == 1
    assert len(catalog) == 2
    assert len(detections) == 2


def test_parse_raw_vulns_handles_missing_agent_ip():
    from app.main import _parse_raw_vulns
    raw = [{
        "agent": {"id": "002", "name": "no-ip-host"},
        "host": {"os": {}},
        "package": {"name": "pkg", "version": "1.0"},
        "vulnerability": {"id": "CVE-X", "severity": "Medium", "score": {}},
    }]
    assets, _, _ = _parse_raw_vulns(raw, "mgr-id")
    assert assets["002"]["ip_address"] is None


# --- Sync Logic Integration ---

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
    """Sincronizar dos veces no debe duplicar assets."""
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


@patch("app.main.fetch_all_vulns", return_value=MOCK_VULN_PAYLOAD)
def test_sync_manager_updates_existing_asset(mock_fetch, db_session):
    """Segundo sync debe actualizar hostname/os del asset existente."""
    from app.main import sync_manager
    manager = _create_manager(db_session)
    sync_manager(db_session, manager)

    mock_fetch.return_value = [{
        **MOCK_VULN_PAYLOAD[0],
        "agent": {"id": "001", "name": "agent-1-RENAMED", "ip": "192.168.1.10"},
    }]
    sync_manager(db_session, manager)

    asset = db_session.query(Asset).first()
    assert asset.hostname == "agent-1-RENAMED"


# --- Scheduler Job ---

@patch("app.main.sync_manager")
def test_run_sync_job_calls_sync_per_manager(mock_sync, db_session):
    from app.main import run_sync_job
    _create_manager(db_session, name="mgr-1")
    _create_manager(db_session, name="mgr-2")

    with patch("app.main.SessionLocal", return_value=db_session):
        run_sync_job()

    assert mock_sync.call_count == 2


@patch("app.main.sync_manager", side_effect=Exception("boom"))
def test_run_sync_job_handles_errors(mock_sync, db_session):
    from app.main import run_sync_job
    _create_manager(db_session)

    with patch("app.main.SessionLocal", return_value=db_session):
        run_sync_job()  # No debe explotar


# --- Wazuh Client ---

@patch("app.wazuh_client._make_request")
def test_fetch_all_vulns_scroll(mock_req):
    from app.wazuh_client import fetch_all_vulns

    first_resp = MagicMock()
    first_resp.json.return_value = {
        "_scroll_id": "scroll-1",
        "hits": {"hits": [{"_source": {"vulnerability": {"id": "CVE-1"}}}]},
    }
    second_resp = MagicMock()
    second_resp.json.return_value = {
        "_scroll_id": "scroll-1",
        "hits": {"hits": []},
    }
    delete_resp = MagicMock()

    mock_req.side_effect = [first_resp, second_resp, delete_resp]

    result = fetch_all_vulns("https://indexer:9200", "admin", "pass")
    assert len(result) == 1
    assert result[0]["vulnerability"]["id"] == "CVE-1"


@patch("app.wazuh_client._make_request")
def test_test_connection_success(mock_req):
    from app.wazuh_client import test_connection
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_req.return_value = mock_resp

    assert test_connection("https://indexer:9200", "admin", "pass") is True


@patch("app.wazuh_client._make_request", side_effect=Exception("timeout"))
def test_test_connection_failure(mock_req):
    from app.wazuh_client import test_connection
    assert test_connection("https://indexer:9200", "admin", "pass") is False


# --- Crypto ---

def test_encrypt_decrypt_roundtrip():
    from app.crypto import encrypt, decrypt
    original = "mi_password_secreta"
    encrypted = encrypt(original)
    assert encrypted != original
    assert decrypt(encrypted) == original


# --- SSL Config ---

@patch.dict("os.environ", {"WAZUH_VERIFY_SSL": "true"}, clear=False)
def test_ssl_verify_enabled():
    import importlib
    import app.wazuh_client as wc
    importlib.reload(wc)
    assert wc.VERIFY_SSL is True


@patch.dict("os.environ", {"WAZUH_SSL_CA_PATH": "/path/to/ca.pem"}, clear=False)
def test_ssl_ca_path():
    import importlib
    import app.wazuh_client as wc
    importlib.reload(wc)
    assert wc._get_ssl_verify() == "/path/to/ca.pem"
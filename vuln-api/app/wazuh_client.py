import requests
from requests.auth import HTTPBasicAuth

def fetch_all_vulns(indexer_url: str, wazuh_user: str, wazuh_password: str, version: str = None):
    index_pattern = _get_index_pattern(version)
    url = f"{indexer_url}/{index_pattern}"
    body = {"size": 10000, "_source": True}

    resp = requests.post(
        url,
        json=body,
        auth=HTTPBasicAuth(wazuh_user, wazuh_password),
        verify=False,
        timeout=60
    )
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]
    return [h["_source"] for h in hits]

def _get_index_pattern(version: str = None) -> str:
    """Ajusta el índice según la versión de Wazuh"""
    if version and version.startswith("4.9"):
        return "wazuh-states-vulnerabilities-*/_search" 
    return "wazuh-states-vulnerabilities-*/_search"     

def test_connection(indexer_url: str, wazuh_user: str, wazuh_password: str) -> bool:
    """Verifica que la conexión sea válida"""
    try:
        resp = requests.get(
            indexer_url,
            auth=HTTPBasicAuth(wazuh_user, wazuh_password),
            verify=False,
            timeout=10
        )
        return resp.status_code == 200
    except Exception:
        return False
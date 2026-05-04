# app/wazuh_client.py
import os
import requests
from requests.auth import HTTPBasicAuth

VULN_INDEX = "wazuh-states-vulnerabilities-*"

# Configurable via env var. En producción con certs válidos, poner True o ruta al CA bundle.
VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() in ("true", "1", "yes")


def _get_ssl_verify():
    """Retorna la configuración de verificación SSL.

    Si WAZUH_SSL_CA_PATH está definida, usa esa ruta como CA bundle.
    Caso contrario, usa el flag booleano WAZUH_VERIFY_SSL.
    """
    ca_path = os.getenv("WAZUH_SSL_CA_PATH")
    if ca_path:
        return ca_path
    return VERIFY_SSL


def _make_request(method, url, auth, headers, timeout=60, **kwargs):
    """Wrapper centralizado para requests con configuración SSL consistente."""
    verify = _get_ssl_verify()
    return requests.request(
        method, url,
        auth=auth,
        headers=headers,
        verify=verify,
        timeout=timeout,
        **kwargs,
    )


def fetch_all_vulns(indexer_url: str, wazuh_user: str, wazuh_password: str):
    """
    Extrae TODAS las vulnerabilidades usando la API de Scroll de Opensearch.
    Esto sortea el límite de index.max_result_window (10,000).
    """
    auth = HTTPBasicAuth(wazuh_user, wazuh_password)
    headers = {"Content-Type": "application/json"}

    # 1. Iniciar el scroll
    url = f"{indexer_url}/{VULN_INDEX}/_search?scroll=2m"
    body = {"size": 5000, "_source": True}

    resp = _make_request("POST", url, auth, headers, json=body)
    resp.raise_for_status()

    data = resp.json()
    scroll_id = data.get("_scroll_id")
    hits = data["hits"]["hits"]
    all_vulns = []

    while hits:
        all_vulns.extend([h["_source"] for h in hits])

        # 2. Scroll para el siguiente lote
        scroll_url = f"{indexer_url}/_search/scroll"
        scroll_body = {"scroll": "2m", "scroll_id": scroll_id}

        scroll_resp = _make_request("POST", scroll_url, auth, headers, json=scroll_body)
        scroll_resp.raise_for_status()

        scroll_data = scroll_resp.json()
        scroll_id = scroll_data.get("_scroll_id")
        hits = scroll_data["hits"]["hits"]

    # 3. Limpiar el contexto de scroll
    _clear_scroll(indexer_url, scroll_id, auth, headers)

    return all_vulns


def _clear_scroll(indexer_url: str, scroll_id, auth, headers):
    """Limpia el contexto de scroll en Opensearch."""
    if not scroll_id:
        return
    try:
        clear_url = f"{indexer_url}/_search/scroll"
        _make_request("DELETE", clear_url, auth, headers, timeout=10, json={"scroll_id": scroll_id})
    except Exception:
        pass  # Falla silenciosa, no es crítico


def test_connection(indexer_url: str, wazuh_user: str, wazuh_password: str) -> bool:
    """Verifica conectividad con el Wazuh Indexer."""
    try:
        auth = HTTPBasicAuth(wazuh_user, wazuh_password)
        headers = {"Content-Type": "application/json"}
        resp = _make_request("GET", indexer_url, auth, headers, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False
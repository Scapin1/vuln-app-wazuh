# app/wazuh_client.py
import requests
from requests.auth import HTTPBasicAuth
import json

VULN_INDEX = "wazuh-states-vulnerabilities-*"

def fetch_all_vulns(indexer_url: str, wazuh_user: str, wazuh_password: str):
    """
    Extrae TODAS las vulnerabilidades usando la API de Scroll de Opensearch.
    Esto sortea el límite de index.max_result_window (10,000).
    """
    auth = HTTPBasicAuth(wazuh_user, wazuh_password)
    headers = {"Content-Type": "application/json"}
    
    # 1. Iniciar el scroll
    url = f"{indexer_url}/{VULN_INDEX}/_search?scroll=2m"
    body = {
        "size": 5000, # Traemos de a 5000 para no matar la ram
        "_source": True
    }
    
    resp = requests.post(url, json=body, auth=auth, verify=False, timeout=60, headers=headers)
    resp.raise_for_status()
    
    data = resp.json()
    scroll_id = data.get("_scroll_id")
    hits = data["hits"]["hits"]
    
    all_vulns = []
    
    while hits:
        all_vulns.extend([h["_source"] for h in hits])
        
        # 2. Hacer scroll para obtener el siguiente lote
        scroll_url = f"{indexer_url}/_search/scroll"
        scroll_body = {
            "scroll": "2m",
            "scroll_id": scroll_id
        }
        
        scroll_resp = requests.post(scroll_url, json=scroll_body, auth=auth, verify=False, timeout=60, headers=headers)
        scroll_resp.raise_for_status()
        
        scroll_data = scroll_resp.json()
        scroll_id = scroll_data.get("_scroll_id")
        hits = scroll_data["hits"]["hits"]
        
    # 3. Limpiar el contexto de scroll
    if scroll_id:
        clear_url = f"{indexer_url}/_search/scroll"
        try:
            requests.delete(clear_url, json={"scroll_id": scroll_id}, auth=auth, verify=False, timeout=10, headers=headers)
        except Exception:
            pass # Falla silenciosa al limpiar, no es critico

    return all_vulns


def test_connection(indexer_url: str, wazuh_user: str, wazuh_password: str) -> bool:
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
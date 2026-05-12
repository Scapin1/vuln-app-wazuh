# app/wazuh_client.py
import httpx
import requests
from requests.auth import HTTPBasicAuth

VULN_INDEX = "wazuh-states-vulnerabilities-*/_search"

async def fetch_all_vulns(indexer_url: str, wazuh_user: str, wazuh_password: str):
    url = f"{indexer_url}/{VULN_INDEX}"
    body = {"size": 10000, "_source": True}
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.post(
            url,
            json=body,
            auth=(wazuh_user, wazuh_password),
            timeout=60.0
        )
        resp.raise_for_status()
    data = resp.json()
    hits = data.get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]
def test_connection(indexer_url: str, wazuh_user: str, wazuh_password: str) -> bool:
    try:
        resp = requests.get(indexer_url, auth=HTTPBasicAuth(wazuh_user, wazuh_password), verify=False, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False
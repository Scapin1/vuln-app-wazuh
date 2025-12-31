# app/wazuh_client.py
import os
import requests

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL").rstrip("/")  # ej: https://wazuh-indexer:9200
WZ_USER = os.getenv("WZ_USER")
WZ_PASS = os.getenv("WZ_PASS")
VERIFY_SSL = os.getenv("WZ_VERIFY_SSL", "false").lower() == "true"

INDEX_PATTERN = "wazuh-states-vulnerabilities-*/_search"

def fetch_all_vulns(page_size=1000):
    """Obtiene todas las vulnerabilidades usando search_after."""
    vulns = []
    search_after = None

    while True:
        body = {
            "size": page_size,
            "sort": [{"_id": "asc"}],
            "query": {"match_all": {}}
        }
        if search_after:
            body["search_after"] = search_after

        resp = requests.post(
            f"{WAZUH_INDEXER_URL}/{INDEX_PATTERN}",
            auth=(WZ_USER, WZ_PASS),
            json=body,
            verify=VERIFY_SSL,
        )
        resp.raise_for_status()
        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            break

        for h in hits:
            vulns.append(h["_source"])

        search_after = hits[-1]["sort"]

    return vulns


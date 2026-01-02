# app/wazuh_client.py
import os
import requests
from requests.auth import HTTPBasicAuth

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WZ_USER = os.getenv("WAZUH_USER")
WZ_PASS = os.getenv("WAZUH_PASSWORD")

INDEX_PATTERN = "wazuh-states-vulnerabilities-*/_search"

def fetch_all_vulns():
    url = f"{WAZUH_INDEXER_URL}/{INDEX_PATTERN}"

    body = {
        "size": 10000,
        "_source": True
    }

    resp = requests.post(
        url,
        json=body,
        auth=HTTPBasicAuth(WZ_USER, WZ_PASS),
        verify=False,
        timeout=60
    )

    resp.raise_for_status()

    hits = resp.json()["hits"]["hits"]

    # Devolvemos solo el _source
    return [h["_source"] for h in hits]

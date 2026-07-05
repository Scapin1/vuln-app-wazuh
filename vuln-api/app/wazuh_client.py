# app/wazuh_client.py
import base64
import httpx
import requests
from typing import Any, Dict, List, AsyncGenerator
from requests.auth import HTTPBasicAuth

VULN_INDEX = "wazuh-states-vulnerabilities-*/_search"




async def fetch_all_vulns(indexer_url: str, wazuh_user: str, wazuh_password: str) -> AsyncGenerator[List[Dict[str, Any]], None]:
    url = f"{indexer_url}/{VULN_INDEX}"
    batch_size = 5000
    search_after = None

    custom_timeout = httpx.Timeout(
    timeout=120.0,
    connect=10.0,
    read=90.0
    )

    credentials = f"{wazuh_user}:{wazuh_password}"
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json"
    }
    async with httpx.AsyncClient(verify=False, timeout=custom_timeout) as client:
        while True:
            body = {
                "size": batch_size,
                "_source": True,
                "sort": [
                    {"vulnerability.detected_at": "asc"},
                    {"_id": "asc"}
                ]
            }
            if search_after:
                body["search_after"] = search_after  
            resp = await client.post(
                url, 
                json=body, 
                headers=headers
            )
            resp.raise_for_status()
            data = resp.json()
        
            hits = data.get("hits", {}).get("hits", [])
            if not hits:
                break

            batch_data = [h["_source"] for h in hits]
            yield batch_data
            search_after = hits[-1]["sort"]

def check_connection(indexer_url: str, wazuh_user: str, wazuh_password: str) -> bool:
    try:
        credentials = f"{wazuh_user}:{wazuh_password}"
        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        headers = {
            "Authorization": f"Basic {encoded_credentials}"
        }
        resp = requests.get(
            indexer_url, 
            headers=headers, 
            verify=False, 
            timeout=10
        )
        return resp.status_code == 200
    except Exception:
        return False
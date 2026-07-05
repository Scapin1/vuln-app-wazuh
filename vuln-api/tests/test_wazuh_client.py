import pytest
import httpx
import requests
from unittest.mock import patch, MagicMock

# --- TESTS PARA FETCH_ALL_VULNS (Generador Asíncrono) ---
from app.wazuh_client import fetch_all_vulns, check_connection

@pytest.mark.asyncio
async def test_fetch_all_vulns_success():
    """
    Simula una paginación exitosa de 2 páginas.
    La primera página devuelve datos y un token de ordenamiento ('sort').
    La segunda página viene vacía para romper el bucle.
    """
    mock_resp_page_1 = MagicMock()
    mock_resp_page_1.json.return_value = {
        "hits": {
            "hits": [
                {"_source": {"vuln": "CVE-1"}, "sort": ["2026-01-01", "id-1"]}
            ]
        }
    }
    mock_resp_page_1.raise_for_status = MagicMock()

    mock_resp_page_2 = MagicMock()
    mock_resp_page_2.json.return_value = {
        "hits": {"hits": []}
    }
    mock_resp_page_2.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.side_effect = [mock_resp_page_1, mock_resp_page_2]

        generator = fetch_all_vulns("http://mock-wazuh", "admin", "password")
        
        batches = []
        async for batch in generator:
            batches.append(batch)

        assert len(batches) == 1  
        assert batches[0] == [{"vuln": "CVE-1"}]
        assert mock_post.call_count == 2  

        second_call_body = mock_post.call_args_list[1][1]["json"]
        assert "search_after" in second_call_body
        assert second_call_body["search_after"] == ["2026-01-01", "id-1"]


@pytest.mark.asyncio
async def test_fetch_all_vulns_http_error():
    """Verifica que si la API del indexer falla, se propague la excepción HTTP."""
    mock_resp_error = MagicMock()
    mock_resp_error.raise_for_status.side_effect = httpx.HTTPStatusError(
        "401 Unauthorized", request=MagicMock(), response=MagicMock()
    )

    with patch("httpx.AsyncClient.post", return_value=mock_resp_error):
        generator = fetch_all_vulns("http://mock-wazuh", "admin", "password")
        
        with pytest.raises(httpx.HTTPStatusError):
            async for _ in generator:
                pass


# --- TESTS PARA TEST_CONNECTION (Síncrono usando 'requests') ---

def test_test_connection_success():
    """Cubre el flujo exitoso (Status 200) de test_connection"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp) as mock_get:
        result = check_connection("http://mock-wazuh", "user", "pass")
        
        assert result is True
        mock_get.assert_called_once()


def test_test_connection_fail_status():
    """Cubre el flujo donde el servidor responde pero con código de error (ej: 401)"""
    mock_resp = MagicMock()
    mock_resp.status_code = 401

    with patch("requests.get", return_value=mock_resp):
        result = check_connection("http://mock-wazuh", "user", "pass")
        
        assert result is False


def test_test_connection_exception():
    """Cubre el bloque 'except Exception' (Error de conexión, timeout, etc)"""
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Timeout/Connection Refused")):
        result = check_connection("http://mock-wazuh", "user", "pass")
        
        assert result is False
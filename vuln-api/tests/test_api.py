import pytest
from unittest.mock import patch

def test_login_fail(client):
    """Prueba que el login falle con credenciales erróneas"""
    response = client.post(
        "/auth/login",
        data={"username": "wrong", "password": "password"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Usuario o contraseña incorrectos"

def test_sync_vulnerabilities_unauthorized(client):
    """Prueba que no se pueda sincronizar sin token"""
    response = client.post("/vulns/sync")
    assert response.status_code == 401

@patch("app.wazuh_client.requests.post")
def test_sync_vulnerabilities_success(mock_post, client, db_session):
    """Prueba el flujo completo de sincronización con Mock de Wazuh"""
    
    # 1. Crear un usuario de prueba directamente en la DB para poder loguearnos
    # Nota: Asegúrate de importar tu lógica de hash o crear el usuario manualmente
    from app.models import User
    from app.auth import pwd_context
    
    test_user = User(username="admin", password_hash=pwd_context.hash("admin"))
    db_session.add(test_user)
    db_session.commit()

    # 2. Obtener Token
    login_res = client.post("/auth/login", data={"username": "admin", "password": "admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Configurar el Mock de la respuesta de Wazuh Indexer
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "agent": {"id": "001", "name": "test-agent"},
                        "vulnerability": {"id": "CVE-2023-1234", "severity": "High", "score": {"base": 7.5}},
                        "package": {"name": "openssl", "version": "1.1.1"},
                        "host": {"os": {"full": "Ubuntu 22.04"}}
                    }
                }
            ]
        }
    }

    # 4. Ejecutar Sync
    sync_res = client.post("/vulns/sync", headers=headers)
    assert sync_res.status_code == 200
    assert sync_res.json()["synced"] == 1

    # 5. Verificar que se guardó en la DB local
    get_res = client.get("/vulns", headers=headers)
    assert len(get_res.json()) == 1
    assert get_res.json()[0]["cve_id"] == "CVE-2023-1234"
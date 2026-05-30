import pytest
from fastapi.testclient import TestClient
from backend.database import init_db
from backend.models import Dispositivo


@pytest.fixture(autouse=True)
def tmp_db():
    init_db()
    yield


from backend.main import app

client = TestClient(app)


def test_crear_dispositivo_en_cliente():
    resp = client.post("/api/dispositivos", json={"ip": "10.0.0.1", "nombre_cliente": "cliente_x"})
    assert resp.status_code == 201

    resp2 = client.get("/api/dispositivos?nombre_cliente=cliente_x")
    data = resp2.json()
    assert len(data) == 1
    assert data[0]["ip"] == "10.0.0.1"


def test_clientes_aislados():
    client.post("/api/dispositivos", json={"ip": "10.0.0.1", "nombre_cliente": "cliente_1"})
    client.post("/api/dispositivos", json={"ip": "10.0.0.2", "nombre_cliente": "cliente_2"})

    resp = client.get("/api/dispositivos?nombre_cliente=cliente_1")
    assert len(resp.json()) == 1
    assert resp.json()[0]["ip"] == "10.0.0.1"

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_index():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"message": "API работает"}


def test_get_items():
    response = client.get("/items")

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2
    assert data[0]["name"] == "Меч"
    assert data[1]["name"] == "Щит"


def test_get_existing_item():
    response = client.get("/items/1")

    assert response.status_code == 200
    assert response.json() == {
        "id": 1,
        "name": "Меч",
    }


def test_get_missing_item():
    response = client.get("/items/999")

    assert response.status_code == 404
    assert response.json() == {
        "detail": {
            "error": "Предмет не найден",
        }
    }

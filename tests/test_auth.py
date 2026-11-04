from tests.conftest import auth_header


def test_register(client):
    res = client.post(
        "/api/auth/register",
        json={"name": "Ava Chen", "email": "ava@soc.local", "password": "Secure123"},
    )
    assert res.status_code == 201
    assert res.get_json()["user"]["role"] == "user"


def test_successful_login(client):
    res = client.post("/api/auth/login", json={"email": "user@soc.local", "password": "User@123"})
    assert res.status_code == 200
    body = res.get_json()
    assert "access_token" in body
    assert body["user"]["email"] == "user@soc.local"


def test_invalid_password(client):
    res = client.post("/api/auth/login", json={"email": "user@soc.local", "password": "wrongpass1"})
    assert res.status_code == 401


def test_repeated_failed_logins_lock(client, app):
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        client.post("/api/auth/login", json={"email": "user@soc.local", "password": "wrongpass1"})
    res = client.post("/api/auth/login", json={"email": "user@soc.local", "password": "User@123"})
    assert res.status_code == 423


def test_jwt_me(client):
    headers = auth_header(client, "user@soc.local", "User@123")
    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["user"]["email"] == "user@soc.local"


def test_unauthorized_admin_access(client):
    headers = auth_header(client, "user@soc.local", "User@123")
    res = client.get("/api/admin/users", headers=headers)
    assert res.status_code == 403


def test_logout_revokes_token(client):
    headers = auth_header(client, "user@soc.local", "User@123")
    res = client.post("/api/auth/logout", headers=headers)
    assert res.status_code == 200
    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 401

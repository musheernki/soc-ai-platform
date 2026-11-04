import pytest

from app import create_app
from extensions import bcrypt, db
from models.user import User


@pytest.fixture()
def app():
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        admin = User(
            name="Admin",
            email="admin@soc.local",
            password_hash=bcrypt.generate_password_hash("Admin@123").decode("utf-8"),
            role="admin",
            account_status="active",
        )
        user = User(
            name="User",
            email="user@soc.local",
            password_hash=bcrypt.generate_password_hash("User@123").decode("utf-8"),
            role="user",
            account_status="active",
        )
        db.session.add_all([admin, user])
        db.session.commit()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def auth_header(client, email, password):
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    token = res.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

import sqlite3

from tests.conftest import login


def test_admin_can_login(client):
    response = login(client, "admin", "admin123")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_regular_user_can_login(client):
    response = login(client, "user", "user123")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_invalid_login_stays_on_login_page(client):
    response = client.post(
        "/login",
        data={"username": "admin", "password": "wrong-password"},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert b"Rendered: login.html" in response.data


def test_login_updates_last_login(client, db_path):
    login(client, "admin", "admin123")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT last_login FROM users WHERE username = ?", ("admin",))
    last_login = cursor.fetchone()[0]
    conn.close()

    assert last_login is not None

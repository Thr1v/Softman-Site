from tests.conftest import login


def test_anonymous_user_is_redirected_from_dashboard(client):
    response = client.get("/", follow_redirects=False)

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_admin_can_access_users_page(client):
    login(client, "admin", "admin123")

    response = client.get("/users")

    assert response.status_code == 200
    assert b"Rendered: users_list.html" in response.data


def test_regular_user_cannot_access_users_page(client):
    login(client, "user", "user123")

    response = client.get("/users", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_regular_user_can_access_normal_logged_in_pages(client):
    login(client, "user", "user123")

    response = client.get("/vendors")

    assert response.status_code == 200
    assert b"Rendered: vendors_list.html" in response.data

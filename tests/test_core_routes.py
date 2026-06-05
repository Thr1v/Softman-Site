import sqlite3
from datetime import datetime, timedelta

import app as app_module
from tests.conftest import login


def test_check_policy_compliance_recent_date_is_compliant():
    recent_date = datetime.now() - timedelta(days=10)

    compliant, days_remaining = app_module.check_policy_compliance(recent_date)

    assert compliant is True
    assert days_remaining > 0


def test_check_policy_compliance_old_date_is_not_compliant():
    old_date = datetime.now() - timedelta(days=400)

    compliant, days_remaining = app_module.check_policy_compliance(old_date)

    assert compliant is False
    assert days_remaining < 0


def test_admin_can_add_vendor(client, db_path):
    login(client, "admin", "admin123")

    response = client.post(
        "/vendors/add",
        data={"vendor_name": "Adobe", "website": "https://adobe.com"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/vendors")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT vendor_name FROM vendors WHERE vendor_name = ?", ("Adobe",))
    vendor = cursor.fetchone()
    conn.close()

    assert vendor is not None


def test_regular_user_can_add_vendor(client, db_path):
    login(client, "user", "user123")

    response = client.post(
        "/vendors/add",
        data={"vendor_name": "User Added Vendor", "website": "https://example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/vendors")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT vendor_name FROM vendors WHERE vendor_name = ?", ("User Added Vendor",))
    vendor = cursor.fetchone()
    conn.close()

    assert vendor is not None


def test_products_api_requires_login(client):
    response = client.get("/api/products/1", follow_redirects=False)

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_products_api_returns_products_for_logged_in_user(client):
    login(client, "user", "user123")

    response = client.get("/api/products/1")

    assert response.status_code == 200
    assert response.get_json() == [
        {"id": 1, "product_name": "Visual Studio", "description": "IDE"}
    ]

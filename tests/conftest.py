import sqlite3
import pytest
from werkzeug.security import generate_password_hash

import app as app_module


@pytest.fixture()
def test_app(tmp_path, monkeypatch):
    """Create a Flask app wired to a temporary SQLite test database."""
    db_path = tmp_path / "test_software_portal.db"

    monkeypatch.setattr(app_module, "DB_PATH", str(db_path))
    monkeypatch.setattr(app_module.app, "secret_key", "test-secret-key")
    app_module.app.config["TESTING"] = True
    app_module.app.config["WTF_CSRF_ENABLED"] = False

    # Your real templates are not needed for route/unit tests. This prevents
    # TemplateNotFound errors while still proving the correct route is reached.
    def fake_render_template(template_name, **context):
        return f"Rendered: {template_name}"

    monkeypatch.setattr(app_module, "render_template", fake_render_template)

    create_test_schema(db_path)
    seed_test_data(db_path)

    yield app_module.app


@pytest.fixture()
def client(test_app):
    return test_app.test_client()


@pytest.fixture()
def db_path():
    return app_module.DB_PATH


def create_test_schema(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            is_superuser INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        );

        CREATE TABLE vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_name TEXT UNIQUE NOT NULL,
            website TEXT,
            is_archived INTEGER NOT NULL DEFAULT 0,
            archived_at TEXT
        );

        CREATE TABLE software_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            description TEXT,
            is_archived INTEGER NOT NULL DEFAULT 0,
            archived_at TEXT,
            UNIQUE(vendor_id, product_name)
        );

        CREATE TABLE software_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            version TEXT NOT NULL,
            license_key TEXT,
            license_type TEXT,
            license_count INTEGER DEFAULT 0,
            installer_filename TEXT,
            installer_path TEXT,
            installer_url TEXT,
            is_latest INTEGER NOT NULL DEFAULT 0,
            release_notes TEXT,
            UNIQUE(product_id, version)
        );

        CREATE TABLE rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_name TEXT UNIQUE NOT NULL,
            building TEXT,
            floor TEXT
        );

        CREATE TABLE installations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version_id INTEGER NOT NULL,
            room_id INTEGER NOT NULL,
            last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT,
            is_long_life INTEGER NOT NULL DEFAULT 0,
            long_life_reason TEXT,
            long_life_approved_by TEXT,
            long_life_approved_at TEXT,
            UNIQUE(version_id, room_id)
        );

        CREATE TABLE update_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            installation_id INTEGER,
            version_id INTEGER,
            room_id INTEGER,
            from_version_id INTEGER,
            to_version_id INTEGER,
            updated_by TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version_id INTEGER NOT NULL,
            room_id INTEGER NOT NULL,
            assigned_to INTEGER NOT NULL,
            assigned_by INTEGER NOT NULL,
            due_date TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            notes TEXT,
            decline_reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT
        );
        """
    )

    conn.commit()
    conn.close()


def seed_test_data(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users (username, password_hash, full_name, email, is_superuser) VALUES (?, ?, ?, ?, ?)",
        ("admin", generate_password_hash("admin123"), "Administrator", "admin@example.com", 1),
    )
    cursor.execute(
        "INSERT INTO users (username, password_hash, full_name, email, is_superuser) VALUES (?, ?, ?, ?, ?)",
        ("user", generate_password_hash("user123"), "Regular User", "user@example.com", 0),
    )

    cursor.execute("INSERT INTO vendors (vendor_name, website) VALUES (?, ?)", ("Microsoft", "https://microsoft.com"))
    vendor_id = cursor.lastrowid

    cursor.execute(
        "INSERT INTO software_products (vendor_id, product_name, description) VALUES (?, ?, ?)",
        (vendor_id, "Visual Studio", "IDE"),
    )
    product_id = cursor.lastrowid

    cursor.execute(
        "INSERT INTO software_versions (product_id, version, is_latest) VALUES (?, ?, ?)",
        (product_id, "1.0", 1),
    )
    version_id = cursor.lastrowid

    cursor.execute("INSERT INTO rooms (room_name, building, floor) VALUES (?, ?, ?)", ("IT1", "Main", "1"))
    room_id = cursor.lastrowid

    cursor.execute(
        "INSERT INTO assignments (version_id, room_id, assigned_to, assigned_by, due_date, notes) VALUES (?, ?, ?, ?, ?, ?)",
        (version_id, room_id, 2, 1, "2026-12-31", "Install latest version"),
    )

    conn.commit()
    conn.close()


def login(client, username="admin", password="admin123"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )

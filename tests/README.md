It includes:

tests/conftest.py
Sets up a temporary SQLite database, seeds an admin and regular user, and patches template rendering so tests do not fail because of missing HTML templates.
tests/test_authentication.py
Tests:
Admin login
Regular user login
Invalid login
last_login update
tests/test_permissions.py
Tests:
Anonymous users are redirected to login
Admin can access /users
Regular user cannot access /users
Regular user can access normal logged-in pages like /vendors
tests/test_core_routes.py
Tests:
check_policy_compliance()
Admin can add vendors
Regular user can add vendors
/api/products/<vendor_id> requires login
Logged-in user can call products API

Your app uses Flask-Login, a superuser_required decorator, user roles, SQLite-backed users, and routes such as /login, /users, /vendors/add, and /api/products/<vendor_id>, so these tests are aimed directly at the important authentication and role-access logic in your uploaded backend.

To use them, place the tests folder next to your app.py, then run:

pip install pytest
pytest -v
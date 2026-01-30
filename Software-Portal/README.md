# Software Management Portal

A comprehensive web-based portal for managing software installations across multiple rooms/locations with a 300-day update policy enforcement system.

## Features

### Core Functionality
- **Software Catalog Management**: Track all software with versions, vendors, licenses, and installers
- **Room/Location Management**: Organize software by rooms, buildings, and floors
- **Installation Tracking**: Monitor which software is installed in each room
- **License Management**: Track license keys, types (Site, Volume, Per-User), and license counts

### Update Management
- **300-Day Policy Enforcement**: Automatically track and flag installations that haven't been updated in 300 days
- **Update Request System**: Create, assign, approve/decline update requests
- **Priority Levels**: Set priority (Low, Normal, High, Critical) for updates
- **Status Tracking**: Track updates through workflow (Pending → Assigned → Approved → Completed)
- **Long-Life Exceptions**: Grant policy exceptions for specific installations with approval tracking
- **Update History**: Complete audit trail of all software updates

### Filtering & Sorting
- Filter installations by room, software, or policy compliance status
- Sort by multiple criteria
- Quick view of policy violations and pending updates

### File Management
- Upload software installers (up to 500MB)
- Download installers directly from the portal
- Secure file storage with sanitized filenames

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. The database will be created automatically on first run from the schema file

## Running the Application

```bash
python app.py
```

The portal will be available at: `http://localhost:5001`

To make it accessible on your network:
- The app is already configured to bind to `0.0.0.0:5001`
- Access from other devices: `http://YOUR_IP:5001`

## Database Schema

### Tables
- **software**: Software catalog with versions, licenses, installers
- **rooms**: Room/location information
- **installations**: Links software to rooms with update tracking
- **update_requests**: Manage update workflow
- **update_history**: Audit log of all updates

### Key Fields
- Installation tracking: `last_updated`, `updated_by`
- Policy enforcement: `is_long_life`, `long_life_reason`, `long_life_approved_by`
- License info: `license_key`, `license_type`, `license_count`
- Installer storage: `installer_filename`, `installer_path`

## Usage Guide

### Adding Software
1. Navigate to "Software" tab
2. Click "Add New Software"
3. Fill in details (name, version, vendor, license info)
4. Optionally upload installer file
5. Submit

### Adding Rooms
1. Go to "Rooms" tab
2. Click "Add New Room"
3. Enter room name, building, floor
4. Submit

### Creating Installations
1. From Dashboard, click "Add Installation"
2. Select software and room
3. Enter version and who installed it
4. Submit

### Managing Updates

#### Creating Update Request
1. Find installation in Dashboard
2. Click "Request Update" (if update available)
3. Set priority and add notes
4. Submit request

#### Processing Update Requests
1. Go to "Updates" tab
2. Filter by status if needed
3. Actions available:
   - **Assign**: Assign to a technician
   - **Approve**: Approve the update
   - **Decline**: Reject with reason
   - **Mark Complete**: Update installation version and create history entry

#### Granting Long-Life Exceptions
1. Find non-compliant installation in Dashboard
2. Click "Grant Exception"
3. Provide reason and approver name
4. Submit

This exempts the installation from the 300-day policy.

## Policy Compliance

### 300-Day Update Policy
- Installations must be updated within 300 days
- Dashboard shows:
  - ✅ **Compliant**: Within 300 days or has long-life exception
  - ❌ **OVERDUE**: Past 300 days without exception
- Days remaining/overdue displayed for each installation

### Policy Violations
- Highlighted in yellow on Dashboard
- Count displayed in statistics
- Can be filtered using Policy filter

## File Upload
- Supported formats: `.exe`, `.msi`, `.dmg`, `.pkg`, `.deb`, `.rpm`, `.zip`
- Maximum size: 500MB
- Files stored in `installers/` folder
- Secure filename sanitization

## Project Structure

```
Software-Portal/
├── app.py                      # Flask application
├── database_schema.sql         # Database schema
├── requirements.txt            # Python dependencies
├── software_management.db      # SQLite database (created on first run)
├── installers/                 # Uploaded installer files
├── static/
│   └── style.css              # Portal styling
└── templates/
    ├── dashboard.html         # Main dashboard
    ├── software_list.html     # Software catalog
    ├── add_software.html      # Add software form
    ├── rooms_list.html        # Rooms overview
    └── update_requests.html   # Update management
```

## API Endpoints

- `GET /`: Dashboard with filters
- `GET /software`: Software list
- `POST /software/add`: Add new software
- `GET /rooms`: Room list
- `POST /rooms/add`: Add new room
- `POST /installation/add`: Add installation
- `GET /updates`: Update requests list
- `POST /updates/create`: Create update request
- `POST /updates/<id>/assign`: Assign update
- `POST /updates/<id>/approve`: Approve update
- `POST /updates/<id>/decline`: Decline update
- `POST /updates/<id>/complete`: Complete update
- `POST /installation/<id>/long-life`: Grant exception
- `POST /installation/<id>/remove-long-life`: Remove exception
- `GET /download/<software_id>`: Download installer
- `GET /api/stats`: Get statistics (JSON)

## Security Notes

⚠️ **Important for Production**:
1. Change `app.secret_key` in app.py
2. Disable debug mode
3. Use a production WSGI server (e.g., Gunicorn)
4. Add authentication/authorization
5. Implement HTTPS
6. Add CSRF protection
7. Validate file uploads more strictly
8. Add rate limiting

## Sample Data

The database schema includes sample data:
- 4 rooms (Lab 101, Lab 102, Office 201, Conference Room A)
- 4 software items (Office 2021, Photoshop 2024, AutoCAD 2024, VS Code)

You can modify or remove this in `database_schema.sql` before first run.

## Customization

### Change Update Policy Duration
In `app.py`, modify:
```python
UPDATE_POLICY_DAYS = 300  # Change to desired number of days
```

### Change Port
In `app.py`, modify:
```python
app.run(debug=True, host='0.0.0.0', port=5001)  # Change port number
```

## Troubleshooting

**Database errors**: Delete `software_management.db` and restart to recreate

**File upload errors**: Check `installers/` folder permissions

**Port already in use**: Change port in `app.py`

**Can't access from network**: Check firewall settings for port 5001

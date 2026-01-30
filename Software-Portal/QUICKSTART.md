# Software Management Portal - Quick Start

## 🎉 Portal is Running!

**Access URLs:**
- Local: http://localhost:5001
- Network: http://172.20.6.225:5001

## 📋 Features Overview

### 1. Dashboard
- View all software installations
- Filter by room, software, or policy compliance
- See policy violations (300-day rule)
- Quick statistics at the top

### 2. Software Management
- Add new software with versions, licenses, installers
- Upload installer files (up to 500MB)
- Download installers
- Track license keys and counts

### 3. Room Management
- Add rooms/locations
- Organize by building and floor
- Track software per room

### 4. Update Request System
**Create Requests:**
- Click "Request Update" on any software needing update
- Set priority (Low/Normal/High/Critical)
- Add notes

**Process Requests:**
- Assign to technicians
- Approve or decline with reasons
- Mark as complete when done

### 5. Policy Enforcement
**300-Day Rule:**
- Software must be updated every 300 days
- Dashboard shows days remaining/overdue
- Policy violations highlighted in yellow

**Long-Life Exceptions:**
- Grant exceptions for specific software
- Requires approval and reason
- Exempts from 300-day policy

## 🚀 Getting Started

1. **Add Rooms**
   - Go to "Rooms" tab
   - Click "Add New Room"
   - Enter room details

2. **Add Software**
   - Go to "Software" tab
   - Click "Add New Software"
   - Fill in details and upload installer (optional)

3. **Create Installations**
   - From Dashboard, click "Add Installation"
   - Select software and room
   - Enter version and installer name

4. **Manage Updates**
   - View pending updates in "Updates" tab
   - Assign, approve, or complete updates

## 📊 Sample Data Included

The portal comes with sample data:
- 4 Rooms (Lab 101, Lab 102, Office 201, Conference Room A)
- 4 Software items (Office, Photoshop, AutoCAD, VS Code)

## 🔧 Configuration

**Change Port:**
Edit `app.py` line 95:
```python
app.run(debug=True, host='0.0.0.0', port=5001)
```

**Change Policy Duration:**
Edit `app.py` line 13:
```python
UPDATE_POLICY_DAYS = 300  # Change to desired days
```

## 📁 File Storage

- Installer files stored in: `c:\Scripts\Apps\Software-Portal\installers\`
- Database: `c:\Scripts\Apps\Software-Portal\software_management.db`

## 🎨 User Interface

- **Green badges**: Compliant or approved
- **Yellow rows**: Policy violations
- **Red badges**: Declined or overdue
- **Blue badges**: Pending or in-progress

## 📱 Responsive Design

The portal works on:
- Desktop computers
- Tablets
- Mobile phones (with scrollable tables)

Enjoy your new Software Management Portal! 🎉

# Logging Documentation

## Overview
The Software Portal application now includes comprehensive logging to monitor operations, security events, and errors.

## Log Files

All logs are stored in the `logs/` folder with automatic rotation (10MB per file, 5 backups retained).

### 1. **app.log**
General application activity and user actions:
- Database initialization
- Vendor/Product/Software additions
- User creation and deletion
- Installations added/deleted
- Vendor archiving operations
- Assignment completions
- File uploads

### 2. **auth.log**
Authentication and authorization events:
- Successful login attempts (username, superuser status, IP address)
- Failed login attempts (username, IP address)
- Logout events (username, IP address)
- Permission denied attempts (user, route, IP address)

### 3. **errors.log**
Error and exception tracking:
- Database errors during login
- File operation failures
- Unexpected exceptions
- All ERROR level messages from app.log and auth.log

## Log Format

### Application & Error Logs
```
YYYY-MM-DD HH:MM:SS - LEVEL - [logger_name] - message - file:line
```
Example:
```
2026-06-05 14:23:45 - INFO - [app] - Vendor added: name='Microsoft', user='admin'
```

### Authentication Logs
```
YYYY-MM-DD HH:MM:SS - LEVEL - message
```
Example:
```
2026-06-05 14:20:12 - INFO - Successful login: user='admin', superuser=1, ip=127.0.0.1
2026-06-05 14:25:30 - WARNING - Failed login attempt: user='hacker', ip=192.168.1.100
```

## What's Logged

### Authentication Events
- ✅ Successful logins (with user, role, and IP)
- ✅ Failed login attempts (with attempted username and IP)
- ✅ User logouts (with username and IP)
- ✅ Permission denied (when non-superuser tries to access restricted routes)

### User Management
- ✅ User account creation (username, superuser status, creator)
- ✅ User deletion (username, deleting admin)

### Vendor & Product Management
- ✅ Vendor additions (name, user)
- ✅ Vendor archiving (name, product count, admin)
- ✅ Product additions (name, vendor, user)
- ✅ Duplicate vendor/product attempts

### Software Management
- ✅ Software version additions (product, vendor, version, user)
- ✅ File uploads (filename, size, user)
- ✅ Duplicate version attempts

### Installations
- ✅ Installation additions (software details, room count, user)
- ✅ Installation deletions (software details, room, admin)
- ✅ Duplicate installation attempts

### Assignments
- ✅ Assignment completions (ID, version, room, user)
- ✅ Failed completion attempts (unauthorized access)

### System Events
- ✅ Application startup (database path, upload folder, debug mode)
- ✅ Database initialization
- ✅ Database schema creation

## Log Rotation

Logs automatically rotate when they reach 10MB. The system keeps:
- Current log file
- 5 backup files (.log.1, .log.2, .log.3, .log.4, .log.5)
- Oldest backups are automatically deleted

## Monitoring Tips

### Watch for Security Issues
```powershell
# Monitor failed login attempts
Get-Content logs\auth.log | Select-String "Failed login"

# Check permission denied events
Get-Content logs\auth.log | Select-String "Access denied"
```

### Track User Activity
```powershell
# See what a specific user has done
Get-Content logs\app.log | Select-String "user='admin'"

# Monitor vendor additions
Get-Content logs\app.log | Select-String "Vendor added"
```

### Monitor Errors
```powershell
# View all errors
Get-Content logs\errors.log

# Count errors in the last hour
# (requires filtering by timestamp)
```

### Real-time Monitoring
```powershell
# Watch auth.log in real-time
Get-Content logs\auth.log -Wait -Tail 10

# Watch all activity in real-time
Get-Content logs\app.log -Wait -Tail 20
```

## Privacy & Security Notes

⚠️ **Important**: Log files contain sensitive information including:
- Usernames and IP addresses
- User activity patterns
- Failed login attempts

**Best Practices**:
1. Restrict access to the `logs/` folder (already in .gitignore)
2. Do not commit logs to version control
3. Archive old logs securely
4. Review logs regularly for suspicious activity
5. Consider encrypting archived logs

## Development Mode

When `app.debug = True`, logs are also printed to the console for easier development monitoring.

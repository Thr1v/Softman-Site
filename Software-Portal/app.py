from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, flash
import sqlite3
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'installers'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

DB_PATH = 'software_management.db'
UPDATE_POLICY_DAYS = 300

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def init_db():
    """Initialize the database from schema file"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    with open('database_schema.sql', 'r') as f:
        cursor.executescript(f.read())
    
    conn.commit()
    conn.close()

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def check_policy_compliance(last_updated):
    """Check if software is within 300-day policy"""
    if not last_updated:
        return False, 300
    
    if isinstance(last_updated, str):
        last_updated = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
    
    days_since_update = (datetime.now() - last_updated).days
    days_remaining = UPDATE_POLICY_DAYS - days_since_update
    
    return days_remaining > 0, days_remaining

@app.route('/')
def index():
    """Main dashboard"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get filter parameters
    room_filter = request.args.get('room', '')
    software_filter = request.args.get('software', '')
    policy_filter = request.args.get('policy', '')  # 'compliant', 'non-compliant', 'all'
    
    # Build query
    query = '''
        SELECT 
            i.id as installation_id,
            s.id as software_id,
            s.software_name,
            s.vendor,
            i.installed_version,
            s.version as latest_version,
            s.license_type,
            s.license_key,
            r.id as room_id,
            r.room_name,
            r.building,
            i.last_updated,
            i.updated_by,
            i.is_long_life,
            i.long_life_reason,
            s.installer_filename
        FROM installations i
        JOIN software s ON i.software_id = s.id
        JOIN rooms r ON i.room_id = r.id
        WHERE 1=1
    '''
    
    params = []
    if room_filter:
        query += ' AND r.room_name LIKE ?'
        params.append(f'%{room_filter}%')
    
    if software_filter:
        query += ' AND s.software_name LIKE ?'
        params.append(f'%{software_filter}%')
    
    query += ' ORDER BY r.room_name, s.software_name'
    
    cursor.execute(query, params)
    installations = []
    
    for row in cursor.fetchall():
        installation = dict(row)
        compliant, days_remaining = check_policy_compliance(installation['last_updated'])
        
        # Apply policy filter
        if policy_filter == 'compliant' and (not compliant and not installation['is_long_life']):
            continue
        elif policy_filter == 'non-compliant' and (compliant or installation['is_long_life']):
            continue
        
        installation['policy_compliant'] = compliant or installation['is_long_life']
        installation['days_remaining'] = days_remaining
        installation['needs_update'] = installation['installed_version'] != installation['latest_version']
        installations.append(installation)
    
    # Get all rooms and software for filters
    cursor.execute('SELECT DISTINCT room_name FROM rooms ORDER BY room_name')
    rooms = [row['room_name'] for row in cursor.fetchall()]
    
    cursor.execute('SELECT DISTINCT software_name FROM software ORDER BY software_name')
    software_list = [row['software_name'] for row in cursor.fetchall()]
    
    # Get pending update requests count
    cursor.execute("SELECT COUNT(*) as count FROM update_requests WHERE status = 'Pending'")
    pending_count = cursor.fetchone()['count']
    
    conn.close()
    
    return render_template('dashboard.html', 
                         installations=installations,
                         rooms=rooms,
                         software_list=software_list,
                         pending_count=pending_count,
                         current_filters={
                             'room': room_filter,
                             'software': software_filter,
                             'policy': policy_filter
                         })

@app.route('/software')
def software_list():
    """View all software"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT s.*, 
               COUNT(i.id) as installation_count
        FROM software s
        LEFT JOIN installations i ON s.id = i.software_id
        GROUP BY s.id
        ORDER BY s.software_name
    ''')
    
    software = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return render_template('software_list.html', software=software)

@app.route('/software/add', methods=['GET', 'POST'])
def add_software():
    """Add new software"""
    if request.method == 'POST':
        conn = get_db()
        cursor = conn.cursor()
        
        # Handle file upload
        installer_filename = None
        installer_path = None
        
        if 'installer' in request.files:
            file = request.files['installer']
            if file.filename:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                installer_filename = filename
                installer_path = filepath
        
        cursor.execute('''
            INSERT INTO software (software_name, version, vendor, license_key, 
                                license_type, license_count, description, 
                                installer_filename, installer_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            request.form['software_name'],
            request.form['version'],
            request.form.get('vendor', ''),
            request.form.get('license_key', ''),
            request.form.get('license_type', ''),
            request.form.get('license_count', 0),
            request.form.get('description', ''),
            installer_filename,
            installer_path
        ))
        
        conn.commit()
        conn.close()
        
        flash('Software added successfully!', 'success')
        return redirect(url_for('software_list'))
    
    return render_template('add_software.html')

@app.route('/rooms')
def rooms_list():
    """View all rooms"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT r.*, COUNT(i.id) as software_count
        FROM rooms r
        LEFT JOIN installations i ON r.id = i.room_id
        GROUP BY r.id
        ORDER BY r.room_name
    ''')
    
    rooms = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return render_template('rooms_list.html', rooms=rooms)

@app.route('/rooms/add', methods=['POST'])
def add_room():
    """Add new room"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO rooms (room_name, building, floor)
        VALUES (?, ?, ?)
    ''', (
        request.form['room_name'],
        request.form.get('building', ''),
        request.form.get('floor', '')
    ))
    
    conn.commit()
    conn.close()
    
    flash('Room added successfully!', 'success')
    return redirect(url_for('rooms_list'))

@app.route('/installation/add', methods=['POST'])
def add_installation():
    """Add software to a room"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO installations (software_id, room_id, installed_version, updated_by)
            VALUES (?, ?, ?, ?)
        ''', (
            request.form['software_id'],
            request.form['room_id'],
            request.form['version'],
            request.form.get('updated_by', 'System')
        ))
        
        conn.commit()
        flash('Installation added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('This software is already installed in this room!', 'error')
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/updates')
def update_requests():
    """View all update requests"""
    conn = get_db()
    cursor = conn.cursor()
    
    status_filter = request.args.get('status', '')
    
    query = '''
        SELECT 
            ur.*,
            s.software_name,
            r.room_name,
            r.building
        FROM update_requests ur
        JOIN software s ON ur.software_id = s.id
        JOIN rooms r ON ur.room_id = r.id
        WHERE 1=1
    '''
    
    params = []
    if status_filter:
        query += ' AND ur.status = ?'
        params.append(status_filter)
    
    query += ' ORDER BY ur.requested_at DESC'
    
    cursor.execute(query, params)
    requests_list = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return render_template('update_requests.html', requests=requests_list, status_filter=status_filter)

@app.route('/updates/create', methods=['POST'])
def create_update_request():
    """Create a new update request"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get installation info
    cursor.execute('''
        SELECT i.*, s.version as latest_version
        FROM installations i
        JOIN software s ON i.software_id = s.id
        WHERE i.id = ?
    ''', (request.form['installation_id'],))
    
    installation = cursor.fetchone()
    
    cursor.execute('''
        INSERT INTO update_requests 
        (installation_id, software_id, room_id, from_version, to_version, 
         requested_by, priority, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        request.form['installation_id'],
        installation['software_id'],
        installation['room_id'],
        installation['installed_version'],
        installation['latest_version'],
        request.form.get('requested_by', 'System'),
        request.form.get('priority', 'Normal'),
        request.form.get('notes', '')
    ))
    
    conn.commit()
    conn.close()
    
    flash('Update request created successfully!', 'success')
    return redirect(url_for('update_requests'))

@app.route('/updates/<int:request_id>/assign', methods=['POST'])
def assign_update(request_id):
    """Assign an update request to someone"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE update_requests 
        SET assigned_to = ?, assigned_at = ?, status = 'Assigned'
        WHERE id = ?
    ''', (request.form['assigned_to'], datetime.now(), request_id))
    
    conn.commit()
    conn.close()
    
    flash('Update request assigned successfully!', 'success')
    return redirect(url_for('update_requests'))

@app.route('/updates/<int:request_id>/approve', methods=['POST'])
def approve_update(request_id):
    """Approve an update request"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE update_requests 
        SET status = 'Approved', approved_by = ?, approved_at = ?
        WHERE id = ?
    ''', (request.form.get('approved_by', 'Admin'), datetime.now(), request_id))
    
    conn.commit()
    conn.close()
    
    flash('Update request approved!', 'success')
    return redirect(url_for('update_requests'))

@app.route('/updates/<int:request_id>/decline', methods=['POST'])
def decline_update(request_id):
    """Decline an update request"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE update_requests 
        SET status = 'Declined', decline_reason = ?
        WHERE id = ?
    ''', (request.form.get('decline_reason', ''), request_id))
    
    conn.commit()
    conn.close()
    
    flash('Update request declined!', 'warning')
    return redirect(url_for('update_requests'))

@app.route('/updates/<int:request_id>/complete', methods=['POST'])
def complete_update(request_id):
    """Mark update as completed"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get request details
    cursor.execute('SELECT * FROM update_requests WHERE id = ?', (request_id,))
    update_req = cursor.fetchone()
    
    # Update installation
    cursor.execute('''
        UPDATE installations 
        SET installed_version = ?, last_updated = ?, updated_by = ?
        WHERE id = ?
    ''', (update_req['to_version'], datetime.now(), 
          request.form.get('completed_by', 'System'), 
          update_req['installation_id']))
    
    # Add to history
    cursor.execute('''
        INSERT INTO update_history 
        (installation_id, software_id, room_id, from_version, to_version, 
         updated_by, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (update_req['installation_id'], update_req['software_id'], 
          update_req['room_id'], update_req['from_version'], 
          update_req['to_version'], 
          request.form.get('completed_by', 'System'),
          request.form.get('notes', '')))
    
    # Mark request as completed
    cursor.execute('''
        UPDATE update_requests 
        SET status = 'Completed', completed_by = ?, completed_at = ?
        WHERE id = ?
    ''', (request.form.get('completed_by', 'System'), datetime.now(), request_id))
    
    conn.commit()
    conn.close()
    
    flash('Update completed successfully!', 'success')
    return redirect(url_for('update_requests'))

@app.route('/installation/<int:installation_id>/long-life', methods=['POST'])
def set_long_life(installation_id):
    """Set software as long-life exception"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE installations 
        SET is_long_life = ?, long_life_reason = ?, 
            long_life_approved_by = ?, long_life_approved_at = ?
        WHERE id = ?
    ''', (
        1,
        request.form.get('reason', ''),
        request.form.get('approved_by', 'Admin'),
        datetime.now(),
        installation_id
    ))
    
    conn.commit()
    conn.close()
    
    flash('Long-life exception granted!', 'success')
    return redirect(url_for('index'))

@app.route('/installation/<int:installation_id>/remove-long-life', methods=['POST'])
def remove_long_life(installation_id):
    """Remove long-life exception"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE installations 
        SET is_long_life = 0, long_life_reason = NULL, 
            long_life_approved_by = NULL, long_life_approved_at = NULL
        WHERE id = ?
    ''', (installation_id,))
    
    conn.commit()
    conn.close()
    
    flash('Long-life exception removed!', 'success')
    return redirect(url_for('index'))

@app.route('/download/<int:software_id>')
def download_installer(software_id):
    """Download software installer"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT installer_path, installer_filename FROM software WHERE id = ?', (software_id,))
    software = cursor.fetchone()
    conn.close()
    
    if software and software['installer_path'] and os.path.exists(software['installer_path']):
        return send_file(software['installer_path'], 
                        as_attachment=True, 
                        download_name=software['installer_filename'])
    else:
        flash('Installer file not found!', 'error')
        return redirect(url_for('index'))

@app.route('/api/stats')
def get_stats():
    """Get dashboard statistics"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Total installations
    cursor.execute('SELECT COUNT(*) as count FROM installations')
    total_installations = cursor.fetchone()['count']
    
    # Non-compliant installations
    cursor.execute('''
        SELECT COUNT(*) as count FROM installations 
        WHERE is_long_life = 0 
        AND julianday('now') - julianday(last_updated) > ?
    ''', (UPDATE_POLICY_DAYS,))
    non_compliant = cursor.fetchone()['count']
    
    # Pending updates
    cursor.execute("SELECT COUNT(*) as count FROM update_requests WHERE status = 'Pending'")
    pending_updates = cursor.fetchone()['count']
    
    # Total software
    cursor.execute('SELECT COUNT(*) as count FROM software')
    total_software = cursor.fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'total_installations': total_installations,
        'non_compliant': non_compliant,
        'pending_updates': pending_updates,
        'total_software': total_software
    })

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5001)

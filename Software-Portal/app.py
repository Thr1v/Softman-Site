from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'installers'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

DB_PATH = 'software_portal.db'
UPDATE_POLICY_DAYS = 300

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class User(UserMixin):
    def __init__(self, id, username, full_name, is_superuser):
        self.id = id
        self.username = username
        self.full_name = full_name
        self.is_superuser = is_superuser

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, full_name, is_superuser FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['full_name'], user_data['is_superuser'])
    return None

def superuser_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_superuser:
            flash('You need superuser privileges to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    with open('database_schema.sql', 'r') as f:
        cursor.executescript(f.read())
    
    cursor.execute('SELECT COUNT(*) as count FROM users')
    if cursor.fetchone()['count'] == 0:
        cursor.execute('INSERT INTO users (username, password_hash, full_name, is_superuser) VALUES (?, ?, ?, ?)',
                      ('admin', generate_password_hash('admin123'), 'Administrator', 1))
        cursor.execute('INSERT INTO users (username, password_hash, full_name, is_superuser) VALUES (?, ?, ?, ?)',
                      ('user', generate_password_hash('user123'), 'Regular User', 0))
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def check_policy_compliance(last_updated):
    if not last_updated:
        return False, 300
    
    if isinstance(last_updated, str):
        try:
            last_updated = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
        except:
            last_updated = datetime.strptime(last_updated[:19], '%Y-%m-%d %H:%M:%S')
    
    days_since_update = (datetime.now() - last_updated).days
    days_remaining = UPDATE_POLICY_DAYS - days_since_update
    
    return days_remaining > 0, days_remaining

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        
        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['username'], user_data['full_name'], user_data['is_superuser'])
            login_user(user, remember=request.form.get('remember', False))
            
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user_data['id']))
            conn.commit()
            conn.close()
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            conn.close()
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/users')
@login_required
@superuser_required
def users_list():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, username, full_name, email, is_superuser, created_at, last_login 
        FROM users 
        ORDER BY username
    ''')
    users = cursor.fetchall()
    conn.close()
    return render_template('users_list.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@superuser_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form.get('full_name', '')
        email = request.form.get('email', '')
        is_superuser = 1 if request.form.get('is_superuser') else 0
        
        password_hash = generate_password_hash(password)
        
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, full_name, email, is_superuser) 
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, full_name, email, is_superuser))
            conn.commit()
            flash(f'User {username} created successfully!', 'success')
            return redirect(url_for('users_list'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'error')
        finally:
            conn.close()
    
    return render_template('add_user.html')

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@superuser_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account!', 'error')
        return redirect(url_for('users_list'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('users_list'))

@app.route('/')
@login_required
def index():
    conn = get_db()
    cursor = conn.cursor()
    
    room_filter = request.args.get('room', '')
    software_filter = request.args.get('software', '')
    policy_filter = request.args.get('policy', '')
    
    query = '''
        SELECT 
            i.id as installation_id, s.id as software_id, s.software_name, s.vendor,
            i.installed_version, s.version as latest_version, s.license_type, s.license_key,
            r.id as room_id, r.room_name, r.building, i.last_updated, i.updated_by,
            i.is_long_life, i.long_life_reason, s.installer_filename
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
        
        if policy_filter == 'compliant' and (not compliant and not installation['is_long_life']):
            continue
        elif policy_filter == 'non-compliant' and (compliant or installation['is_long_life']):
            continue
        
        installation['policy_compliant'] = compliant or installation['is_long_life']
        installation['days_remaining'] = days_remaining
        installation['needs_update'] = installation['installed_version'] != installation['latest_version']
        installations.append(installation)
    
    cursor.execute('SELECT DISTINCT room_name FROM rooms ORDER BY room_name')
    rooms = [row['room_name'] for row in cursor.fetchall()]
    
    cursor.execute('SELECT DISTINCT software_name FROM software ORDER BY software_name')
    software_list = [row['software_name'] for row in cursor.fetchall()]
    
    cursor.execute('SELECT id, room_name FROM rooms ORDER BY room_name')
    rooms_with_ids = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute('SELECT id, software_name, version FROM software ORDER BY software_name')
    software_with_ids = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template('dashboard.html', 
                         installations=installations, rooms=rooms, software_list=software_list,
                         rooms_with_ids=rooms_with_ids, software_with_ids=software_with_ids,
                         current_filters={'room': room_filter, 'software': software_filter, 'policy': policy_filter})

@app.route('/software')
@login_required
def software_list():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.*, COUNT(i.id) as installation_count
        FROM software s LEFT JOIN installations i ON s.id = i.software_id
        GROUP BY s.id ORDER BY s.software_name
    ''')
    software = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return render_template('software_list.html', software=software)

@app.route('/software/add', methods=['GET', 'POST'])
@superuser_required
def add_software():
    if request.method == 'POST':
        conn = get_db()
        cursor = conn.cursor()
        
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
                                license_type, license_count, description, installer_filename, installer_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (request.form['software_name'], request.form['version'], request.form.get('vendor', ''),
              request.form.get('license_key', ''), request.form.get('license_type', ''),
              request.form.get('license_count', 0), request.form.get('description', ''),
              installer_filename, installer_path))
        
        conn.commit()
        conn.close()
        flash('Software added successfully!', 'success')
        return redirect(url_for('software_list'))
    
    return render_template('add_software.html')

@app.route('/software/<int:software_id>/delete', methods=['POST'])
@superuser_required
def delete_software(software_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) as count FROM installations WHERE software_id = ?', (software_id,))
    count = cursor.fetchone()['count']
    
    if count > 0:
        flash(f'Cannot delete software with {count} active installations.', 'error')
    else:
        cursor.execute('SELECT installer_path FROM software WHERE id = ?', (software_id,))
        software = cursor.fetchone()
        if software and software['installer_path'] and os.path.exists(software['installer_path']):
            try:
                os.remove(software['installer_path'])
            except:
                pass
        cursor.execute('DELETE FROM software WHERE id = ?', (software_id,))
        conn.commit()
        flash('Software deleted successfully!', 'success')
    
    conn.close()
    return redirect(url_for('software_list'))

@app.route('/rooms')
@login_required
def rooms_list():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, COUNT(i.id) as software_count
        FROM rooms r LEFT JOIN installations i ON r.id = i.room_id
        GROUP BY r.id ORDER BY r.room_name
    ''')
    rooms = cursor.fetchall()
    conn.close()
    return render_template('rooms_list.html', rooms=rooms)

@app.route('/rooms/<int:room_id>')
@login_required
def room_details(room_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get room info
    cursor.execute('SELECT * FROM rooms WHERE id = ?', (room_id,))
    room = cursor.fetchone()
    
    if not room:
        flash('Room not found!', 'error')
        return redirect(url_for('rooms_list'))
    
    # Get all software installed in this room
    cursor.execute('''
        SELECT 
            i.id as installation_id, s.id as software_id, s.software_name, s.vendor,
            i.installed_version, s.version as latest_version, i.last_updated, 
            i.updated_by, i.is_long_life, i.long_life_reason,
            CAST((julianday('now') - julianday(i.last_updated)) AS INTEGER) as days_since_update
        FROM installations i
        JOIN software s ON i.software_id = s.id
        WHERE i.room_id = ?
        ORDER BY s.software_name
    ''', (room_id,))
    installations = cursor.fetchall()
    
    conn.close()
    return render_template('room_details.html', room=room, installations=installations, update_policy_days=UPDATE_POLICY_DAYS)


@app.route('/rooms/add', methods=['POST'])
@superuser_required
def add_room():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO rooms (room_name, building, floor) VALUES (?, ?, ?)',
                  (request.form['room_name'], request.form.get('building', ''), request.form.get('floor', '')))
    conn.commit()
    conn.close()
    flash('Room added successfully!', 'success')
    return redirect(url_for('rooms_list'))

@app.route('/rooms/<int:room_id>/delete', methods=['POST'])
@superuser_required
def delete_room(room_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) as count FROM installations WHERE room_id = ?', (room_id,))
    count = cursor.fetchone()['count']
    
    if count > 0:
        flash(f'Cannot delete room with {count} software installations.', 'error')
    else:
        cursor.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
        conn.commit()
        flash('Room deleted successfully!', 'success')
    
    conn.close()
    return redirect(url_for('rooms_list'))

@app.route('/installation/add', methods=['POST'])
@login_required
def add_installation():
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO installations (software_id, room_id, installed_version, updated_by)
            VALUES (?, ?, ?, ?)
        ''', (request.form['software_id'], request.form['room_id'], request.form['version'],
              current_user.full_name or current_user.username))
        conn.commit()
        flash('Installation added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('This software is already installed in this room!', 'error')
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/installation/<int:installation_id>/delete', methods=['POST'])
@superuser_required
def delete_installation(installation_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM installations WHERE id = ?', (installation_id,))
    conn.commit()
    conn.close()
    flash('Installation deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/installation/<int:installation_id>/update', methods=['POST'])
@superuser_required
def update_installation(installation_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT s.version, i.software_id, i.room_id, i.installed_version FROM installations i JOIN software s ON i.software_id = s.id WHERE i.id = ?',
                  (installation_id,))
    inst = cursor.fetchone()
    
    cursor.execute('UPDATE installations SET installed_version = ?, last_updated = ?, updated_by = ? WHERE id = ?',
                  (inst['version'], datetime.now(), current_user.full_name or current_user.username, installation_id))
    
    cursor.execute('INSERT INTO update_history (installation_id, software_id, room_id, from_version, to_version, updated_by) VALUES (?, ?, ?, ?, ?, ?)',
                  (installation_id, inst['software_id'], inst['room_id'], inst['installed_version'], inst['version'],
                   current_user.full_name or current_user.username))
    
    conn.commit()
    conn.close()
    flash('Installation updated successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/installation/<int:installation_id>/long-life', methods=['POST'])
@superuser_required
def set_long_life(installation_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE installations 
        SET is_long_life = 1, long_life_reason = ?, long_life_approved_by = ?, long_life_approved_at = ?
        WHERE id = ?
    ''', (request.form.get('reason', ''), current_user.full_name or current_user.username, datetime.now(), installation_id))
    conn.commit()
    conn.close()
    flash('Long-life exception granted!', 'success')
    return redirect(url_for('index'))

@app.route('/installation/<int:installation_id>/remove-long-life', methods=['POST'])
@superuser_required
def remove_long_life(installation_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE installations SET is_long_life = 0, long_life_reason = NULL, long_life_approved_by = NULL, long_life_approved_at = NULL WHERE id = ?',
                  (installation_id,))
    conn.commit()
    conn.close()
    flash('Long-life exception removed!', 'success')
    return redirect(url_for('index'))

@app.route('/download/<int:software_id>')
@login_required
def download_installer(software_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT installer_path, installer_filename FROM software WHERE id = ?', (software_id,))
    software = cursor.fetchone()
    conn.close()
    
    if software and software['installer_path'] and os.path.exists(software['installer_path']):
        return send_file(software['installer_path'], as_attachment=True, download_name=software['installer_filename'])
    else:
        flash('Installer file not found!', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(debug=True, host='0.0.0.0', port=5001)

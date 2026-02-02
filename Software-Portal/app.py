from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('app_secret')
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
@app.context_processor
def inject_pending_assignments():
    """Make pending assignments count available to all templates"""
    if current_user.is_authenticated:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) as count 
            FROM assignments 
            WHERE assigned_to = ? AND status = 'pending'
        ''', (current_user.id,))
        result = cursor.fetchone()
        conn.close()
        return {'pending_assignments_count': result['count'] if result else 0}
    return {'pending_assignments_count': 0}
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

@app.route('/vendors')
@login_required
def vendors_list():
    show_archived = request.args.get('show_archived', 'false') == 'true'
    
    conn = get_db()
    cursor = conn.cursor()
    
    if show_archived:
        cursor.execute('''
            SELECT v.*, COUNT(DISTINCT sp.id) as product_count
            FROM vendors v 
            LEFT JOIN software_products sp ON v.id = sp.vendor_id
            GROUP BY v.id 
            ORDER BY v.is_archived, v.vendor_name
        ''')
    else:
        cursor.execute('''
            SELECT v.*, COUNT(DISTINCT sp.id) as product_count
            FROM vendors v 
            LEFT JOIN software_products sp ON v.id = sp.vendor_id
            WHERE v.is_archived = 0
            GROUP BY v.id 
            ORDER BY v.vendor_name
        ''')
    
    vendors = cursor.fetchall()
    
    # Get products for each vendor
    vendor_products = {}
    for vendor in vendors:
        cursor.execute('''
            SELECT id, product_name, description, is_archived
            FROM software_products
            WHERE vendor_id = ?
            ORDER BY is_archived, product_name
        ''', (vendor['id'],))
        vendor_products[vendor['id']] = cursor.fetchall()
    
    conn.close()
    return render_template('vendors_list.html', vendors=vendors, vendor_products=vendor_products, show_archived=show_archived)

@app.route('/vendors/add', methods=['GET', 'POST'])
@login_required
@superuser_required
def add_vendor():
    if request.method == 'POST':
        vendor_name = request.form['vendor_name']
        website = request.form.get('website', '')
        
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO vendors (vendor_name, website) VALUES (?, ?)',
                          (vendor_name, website))
            conn.commit()
            flash(f'Vendor {vendor_name} added successfully!', 'success')
            return redirect(url_for('vendors_list'))
        except sqlite3.IntegrityError:
            flash('Vendor already exists!', 'error')
        finally:
            conn.close()
    
    return render_template('add_vendor.html')

@app.route('/vendors/<int:vendor_id>/archive', methods=['POST'])
@login_required
@superuser_required
def archive_vendor(vendor_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if vendor has products
    cursor.execute('SELECT COUNT(*) as count FROM software_products WHERE vendor_id = ?', (vendor_id,))
    product_count = cursor.fetchone()['count']
    
    # Check if any of the vendor's products have versions with active installations
    cursor.execute('''
        SELECT COUNT(DISTINCT i.id) as count
        FROM installations i
        JOIN software_versions sv ON i.version_id = sv.id
        JOIN software_products sp ON sv.product_id = sp.id
        WHERE sp.vendor_id = ?
    ''', (vendor_id,))
    installation_count = cursor.fetchone()['count']
    
    # Check if vendor has active assignments
    cursor.execute('''
        SELECT COUNT(DISTINCT a.id) as count
        FROM assignments a
        JOIN software_versions sv ON a.version_id = sv.id
        JOIN software_products sp ON sv.product_id = sp.id
        WHERE sp.vendor_id = ?
        AND a.status != 'completed'
    ''', (vendor_id,))
    assignment_count = cursor.fetchone()['count']
    
    if installation_count > 0 or assignment_count > 0:
        flash(f'Cannot archive vendor: {installation_count} active installation(s) and {assignment_count} pending assignment(s). '
              f'Please remove all installations and complete assignments before archiving.', 'error')
    else:
        cursor.execute('''
            UPDATE vendors 
            SET is_archived = 1, archived_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (vendor_id,))
        conn.commit()
        
        cursor.execute('SELECT vendor_name FROM vendors WHERE id = ?', (vendor_id,))
        vendor_name = cursor.fetchone()['vendor_name']
        flash(f'Vendor "{vendor_name}" archived successfully! '
              f'({product_count} product(s) also archived)', 'success')
    
    conn.close()
    return redirect(url_for('vendors_list'))

@app.route('/vendors/<int:vendor_id>/unarchive', methods=['POST'])
@login_required
@superuser_required
def unarchive_vendor(vendor_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE vendors 
        SET is_archived = 0, archived_at = NULL 
        WHERE id = ?
    ''', (vendor_id,))
    conn.commit()
    
    cursor.execute('SELECT vendor_name FROM vendors WHERE id = ?', (vendor_id,))
    vendor_name = cursor.fetchone()['vendor_name']
    flash(f'Vendor "{vendor_name}" unarchived successfully!', 'success')
    
    conn.close()
    return redirect(url_for('vendors_list', show_archived='true'))

@app.route('/products/add', methods=['POST'])
@login_required
@superuser_required
def add_product():
    vendor_id = request.form['vendor_id']
    product_name = request.form['product_name']
    description = request.form.get('description', '')
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO software_products (vendor_id, product_name, description) VALUES (?, ?, ?)',
                      (vendor_id, product_name, description))
        conn.commit()
        flash(f'Product {product_name} added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Product already exists for this vendor!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('vendors_list'))

@app.route('/products/<int:product_id>/edit', methods=['POST'])
@login_required
@superuser_required
def edit_product(product_id):
    product_name = request.form['product_name']
    description = request.form.get('description', '')
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE software_products 
            SET product_name = ?, description = ? 
            WHERE id = ?
        ''', (product_name, description, product_id))
        conn.commit()
        flash(f'Product updated successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('A product with this name already exists for this vendor!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('vendors_list'))

@app.route('/products/<int:product_id>/archive', methods=['POST'])
@login_required
@superuser_required
def archive_product(product_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if product has versions with active installations
    cursor.execute('''
        SELECT COUNT(DISTINCT i.id) as count
        FROM installations i
        JOIN software_versions sv ON i.version_id = sv.id
        WHERE sv.product_id = ?
    ''', (product_id,))
    installation_count = cursor.fetchone()['count']
    
    # Check if product has active assignments
    cursor.execute('''
        SELECT COUNT(DISTINCT a.id) as count
        FROM assignments a
        JOIN software_versions sv ON a.version_id = sv.id
        WHERE sv.product_id = ?
        AND a.status != 'completed'
    ''', (product_id,))
    assignment_count = cursor.fetchone()['count']
    
    if installation_count > 0 or assignment_count > 0:
        flash(f'Cannot archive product: {installation_count} active installation(s) and {assignment_count} pending assignment(s). '
              f'Please remove all installations and complete assignments before archiving.', 'error')
    else:
        cursor.execute('''
            UPDATE software_products 
            SET is_archived = 1, archived_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (product_id,))
        conn.commit()
        
        cursor.execute('SELECT product_name FROM software_products WHERE id = ?', (product_id,))
        product_name = cursor.fetchone()['product_name']
        flash(f'Product "{product_name}" archived successfully!', 'success')
    
    conn.close()
    return redirect(url_for('vendors_list'))

@app.route('/products/<int:product_id>/unarchive', methods=['POST'])
@login_required
@superuser_required
def unarchive_product(product_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE software_products 
        SET is_archived = 0, archived_at = NULL 
        WHERE id = ?
    ''', (product_id,))
    conn.commit()
    
    cursor.execute('SELECT product_name FROM software_products WHERE id = ?', (product_id,))
    product_name = cursor.fetchone()['product_name']
    flash(f'Product "{product_name}" unarchived successfully!', 'success')
    
    conn.close()
    return redirect(url_for('vendors_list'))

@app.route('/compliance')
@login_required
@superuser_required
def compliance_report():
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all rooms with their compliance status
    cursor.execute('''
        SELECT 
            r.id as room_id, r.room_name, r.building, r.floor,
            COUNT(i.id) as total_installations,
            SUM(CASE WHEN CAST((julianday('now') - julianday(i.last_updated)) AS INTEGER) > ? 
                AND i.is_long_life = 0 THEN 1 ELSE 0 END) as out_of_policy_count,
            SUM(CASE WHEN CAST((julianday('now') - julianday(i.last_updated)) AS INTEGER) > ? - 30
                AND CAST((julianday('now') - julianday(i.last_updated)) AS INTEGER) <= ?
                AND i.is_long_life = 0 THEN 1 ELSE 0 END) as warning_count,
            MIN(CASE WHEN i.is_long_life = 0 
                THEN CAST((julianday('now') - julianday(i.last_updated)) AS INTEGER) END) as oldest_update_days
        FROM rooms r
        LEFT JOIN installations i ON r.id = i.room_id
        GROUP BY r.id
        HAVING total_installations > 0
        ORDER BY out_of_policy_count DESC, warning_count DESC, oldest_update_days DESC
    ''', (UPDATE_POLICY_DAYS, UPDATE_POLICY_DAYS, UPDATE_POLICY_DAYS))
    rooms = cursor.fetchall()
    
    # Get detailed breakdown for each room
    room_details = {}
    for room in rooms:
        cursor.execute('''
            SELECT 
                i.id as installation_id, v.vendor_name, sp.product_name, sv.version, i.last_updated,
                CAST((julianday('now') - julianday(i.last_updated)) AS INTEGER) as days_since_update,
                i.is_long_life, i.long_life_reason, i.updated_by
            FROM installations i
            JOIN software_versions sv ON i.version_id = sv.id
            JOIN software_products sp ON sv.product_id = sp.id
            JOIN vendors v ON sp.vendor_id = v.id
            WHERE i.room_id = ?
            AND (CAST((julianday('now') - julianday(i.last_updated)) AS INTEGER) > ? - 30
                 OR i.is_long_life = 1)
            ORDER BY days_since_update DESC
        ''', (room['room_id'], UPDATE_POLICY_DAYS))
        room_details[room['room_id']] = cursor.fetchall()
    
    conn.close()
    return render_template('compliance_report.html', rooms=rooms, room_details=room_details, 
                          update_policy_days=UPDATE_POLICY_DAYS)

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
            i.id as installation_id, sv.id as version_id, 
            v.vendor_name, sp.product_name,
            sv.version as installed_version, sv.license_type, sv.license_key,
            r.id as room_id, r.room_name, r.building, i.last_updated, i.updated_by,
            i.is_long_life, i.long_life_reason, sv.installer_filename,
            latest.version as latest_version, latest.id as latest_version_id
        FROM installations i
        JOIN software_versions sv ON i.version_id = sv.id
        JOIN software_products sp ON sv.product_id = sp.id
        JOIN vendors v ON sp.vendor_id = v.id
        JOIN rooms r ON i.room_id = r.id
        LEFT JOIN software_versions latest ON sp.id = latest.product_id AND latest.is_latest = 1
        WHERE 1=1
    '''
    
    params = []
    if room_filter:
        query += ' AND r.room_name LIKE ?'
        params.append(f'%{room_filter}%')
    
    if software_filter:
        query += ' AND (sp.product_name LIKE ? OR v.vendor_name LIKE ?)'
        params.append(f'%{software_filter}%')
        params.append(f'%{software_filter}%')
    
    query += ' ORDER BY r.room_name, v.vendor_name, sp.product_name'
    
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
    
    cursor.execute('SELECT DISTINCT sp.product_name FROM software_products sp ORDER BY sp.product_name')
    software_list = [row['product_name'] for row in cursor.fetchall()]
    
    cursor.execute('SELECT id, room_name FROM rooms ORDER BY room_name')
    rooms_with_ids = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute('''
        SELECT sv.id, v.vendor_name, sp.product_name, sv.version, sv.is_latest
        FROM software_versions sv
        JOIN software_products sp ON sv.product_id = sp.id
        JOIN vendors v ON sp.vendor_id = v.id
        WHERE sv.is_latest = 1
        ORDER BY v.vendor_name, sp.product_name
    ''')
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
        SELECT 
            v.vendor_name, v.id as vendor_id,
            sp.product_name, sp.id as product_id, sp.description,
            sv.id as version_id, sv.version, sv.is_latest, sv.license_type, sv.license_key,
            sv.license_count, sv.installer_filename, sv.installer_url,
            COUNT(i.id) as installation_count
        FROM vendors v
        JOIN software_products sp ON v.id = sp.vendor_id
        JOIN software_versions sv ON sp.id = sv.product_id
        LEFT JOIN installations i ON sv.id = i.version_id
        WHERE v.is_archived = 0
        GROUP BY sv.id
        ORDER BY v.vendor_name, sp.product_name, sv.is_latest DESC, sv.version DESC
    ''')
    software = [dict(row) for row in cursor.fetchall()]
    
    # Get vendors and products for the add form
    cursor.execute('SELECT id, vendor_name FROM vendors WHERE is_archived = 0 ORDER BY vendor_name')
    vendors = cursor.fetchall()
    
    conn.close()
    return render_template('software_list.html', software=software, vendors=vendors)

@app.route('/software/add', methods=['GET', 'POST'])
@superuser_required
def add_software():
    if request.method == 'POST':
        conn = get_db()
        cursor = conn.cursor()
        
        product_id = request.form['product_id']
        version = request.form['version']
        is_latest = 1 if request.form.get('is_latest') else 0
        
        # If marking as latest, unmark previous latest version
        if is_latest:
            cursor.execute('UPDATE software_versions SET is_latest = 0 WHERE product_id = ?', (product_id,))
        
        installer_filename = None
        installer_path = None
        installer_url = request.form.get('installer_url', '').strip()
        
        if 'installer' in request.files:
            file = request.files['installer']
            if file.filename:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                installer_filename = filename
                installer_path = filepath
                installer_url = None  # Clear URL if file is uploaded
        
        try:
            cursor.execute('''
                INSERT INTO software_versions (product_id, version, license_key, 
                                    license_type, license_count, installer_filename, 
                                    installer_path, installer_url, is_latest, release_notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (product_id, version, request.form.get('license_key', ''),
                  request.form.get('license_type', ''), request.form.get('license_count', 0),
                  installer_filename, installer_path, installer_url if installer_url else None,
                  is_latest, request.form.get('release_notes', '')))
            
            conn.commit()
            flash('Software version added successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('This version already exists for this product!', 'error')
        finally:
            conn.close()
        
        return redirect(url_for('software_list'))
    
    # GET request
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, vendor_name FROM vendors WHERE is_archived = 0 ORDER BY vendor_name')
    vendors = cursor.fetchall()
    conn.close()
    
    return render_template('add_software.html', vendors=vendors)

@app.route('/software/<int:version_id>/delete', methods=['POST'])
@superuser_required
def delete_software(version_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) as count FROM installations WHERE version_id = ?', (version_id,))
    count = cursor.fetchone()['count']
    
    if count > 0:
        flash(f'Cannot delete software version with {count} active installations.', 'error')
    else:
        cursor.execute('SELECT installer_path FROM software_versions WHERE id = ?', (version_id,))
        software = cursor.fetchone()
        if software and software['installer_path'] and os.path.exists(software['installer_path']):
            try:
                os.remove(software['installer_path'])
            except:
                pass
        cursor.execute('DELETE FROM software_versions WHERE id = ?', (version_id,))
        conn.commit()
        flash('Software version deleted successfully!', 'success')
    
    conn.close()
    return redirect(url_for('software_list'))

@app.route('/api/products/<int:vendor_id>')
@login_required
def get_products_by_vendor(vendor_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, product_name, description FROM software_products WHERE vendor_id = ? ORDER BY product_name', (vendor_id,))
    products = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(products)

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
            i.id as installation_id, sv.id as version_id,
            v.vendor_name, sp.product_name, sv.version as installed_version,
            latest.version as latest_version, i.last_updated, 
            i.updated_by, i.is_long_life, i.long_life_reason,
            CAST((julianday('now') - julianday(i.last_updated)) AS INTEGER) as days_since_update
        FROM installations i
        JOIN software_versions sv ON i.version_id = sv.id
        JOIN software_products sp ON sv.product_id = sp.id
        JOIN vendors v ON sp.vendor_id = v.id
        LEFT JOIN software_versions latest ON sp.id = latest.product_id AND latest.is_latest = 1
        WHERE i.room_id = ?
        ORDER BY v.vendor_name, sp.product_name
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
        version_id = request.form['version_id']
        room_ids = request.form.getlist('room_ids')  # Get multiple room IDs
        
        # Insert installation for each selected room
        for room_id in room_ids:
            cursor.execute('''
                INSERT INTO installations (version_id, room_id, updated_by)
                VALUES (?, ?, ?)
            ''', (version_id, room_id, current_user.username))
        conn.commit()
        flash('Installation added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('This software version is already installed in this room!', 'error')
    
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
    
    # Get current installation and find latest version
    cursor.execute('''
        SELECT i.version_id as old_version_id, i.room_id, sv.product_id,
               latest.id as latest_version_id, latest.version as latest_version,
               old_sv.version as old_version
        FROM installations i
        JOIN software_versions old_sv ON i.version_id = old_sv.id
        JOIN software_versions sv ON i.version_id = sv.id
        LEFT JOIN software_versions latest ON sv.product_id = latest.product_id AND latest.is_latest = 1
        WHERE i.id = ?
    ''', (installation_id,))
    inst = cursor.fetchone()
    
    if inst and inst['latest_version_id']:
        # Update to latest version
        cursor.execute('UPDATE installations SET version_id = ?, last_updated = ?, updated_by = ? WHERE id = ?',
                      (inst['latest_version_id'], datetime.now(), current_user.full_name or current_user.username, installation_id))
        
        cursor.execute('''
            INSERT INTO update_history (installation_id, version_id, room_id, from_version_id, to_version_id, updated_by) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (installation_id, inst['latest_version_id'], inst['room_id'], inst['old_version_id'], 
              inst['latest_version_id'], current_user.full_name or current_user.username))
        
        conn.commit()
        flash('Installation updated to latest version successfully!', 'success')
    else:
        flash('No latest version available for this product.', 'error')
    
    conn.close()
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

@app.route('/assignments')
@login_required
def my_assignments():
    conn = get_db()
    cursor = conn.cursor()
    
    if current_user.is_superuser:
        # Superusers see ALL assignments
        cursor.execute('''
            SELECT 
                a.id, a.due_date, a.status, a.notes, a.created_at, a.decline_reason, a.completed_at,
                v.vendor_name, sp.product_name, sv.version, r.room_name,
                u1.username as assigned_to_name,
                u2.username as assigned_by_name
            FROM assignments a
            JOIN software_versions sv ON a.version_id = sv.id
            JOIN software_products sp ON sv.product_id = sp.id
            JOIN vendors v ON sp.vendor_id = v.id
            JOIN rooms r ON a.room_id = r.id
            JOIN users u1 ON a.assigned_to = u1.id
            JOIN users u2 ON a.assigned_by = u2.id
            ORDER BY 
                CASE a.status 
                    WHEN 'pending' THEN 1 
                    WHEN 'declined' THEN 2
                    WHEN 'completed' THEN 3 
                    ELSE 4 
                END,
                a.due_date, a.created_at DESC
        ''')
    else:
        # Regular users see only their assignments
        cursor.execute('''
            SELECT 
                a.id, a.due_date, a.status, a.notes, a.created_at, a.decline_reason,
                v.vendor_name, sp.product_name, sv.version, r.room_name,
                u.username as assigned_by_name
            FROM assignments a
            JOIN software_versions sv ON a.version_id = sv.id
            JOIN software_products sp ON sv.product_id = sp.id
            JOIN vendors v ON sp.vendor_id = v.id
            JOIN rooms r ON a.room_id = r.id
            JOIN users u ON a.assigned_by = u.id
            WHERE a.assigned_to = ?
            ORDER BY 
                CASE a.status 
                    WHEN 'pending' THEN 1 
                    WHEN 'completed' THEN 2 
                    WHEN 'declined' THEN 3
                    ELSE 4 
                END,
                a.due_date
        ''', (current_user.id,))
    
    assignments = cursor.fetchall()
    
    # If superuser, get data for assignment creation
    software_list = []
    users = []
    rooms = []
    if current_user.is_superuser:
        cursor.execute('''
            SELECT sv.id, v.vendor_name, sp.product_name, sv.version, sv.is_latest
            FROM software_versions sv
            JOIN software_products sp ON sv.product_id = sp.id
            JOIN vendors v ON sp.vendor_id = v.id
            WHERE sv.is_latest = 1
            ORDER BY v.vendor_name, sp.product_name
        ''')
        software_list = cursor.fetchall()
        cursor.execute('SELECT id, username FROM users ORDER BY username')
        users = cursor.fetchall()
        cursor.execute('SELECT id, room_name, building FROM rooms ORDER BY building, room_name')
        rooms = cursor.fetchall()
    
    conn.close()
    
    return render_template('my_assignments.html', 
                          assignments=assignments,
                          software_list=software_list,
                          users=users,
                          rooms=rooms,
                          now=datetime.now().strftime('%Y-%m-%d'))

@app.route('/assignments/<int:assignment_id>/complete', methods=['POST'])
@login_required
def complete_assignment(assignment_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify assignment belongs to current user
    cursor.execute('SELECT * FROM assignments WHERE id = ? AND assigned_to = ?', 
                  (assignment_id, current_user.id))
    assignment = cursor.fetchone()
    
    if assignment:
        cursor.execute('''
            UPDATE assignments 
            SET status = 'completed', completed_at = ? 
            WHERE id = ?
        ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), assignment_id))
        
        # Also create the installation (or ignore if already exists)
        cursor.execute('''
            INSERT OR IGNORE INTO installations (version_id, room_id, updated_by)
            VALUES (?, ?, ?)
        ''', (assignment['version_id'], assignment['room_id'], current_user.username))
        
        conn.commit()
        flash('Assignment marked as completed!', 'success')
    else:
        flash('Assignment not found!', 'error')
    
    conn.close()
    return redirect(url_for('my_assignments'))

@app.route('/assignments/<int:assignment_id>/incomplete', methods=['POST'])
@login_required
def incomplete_assignment(assignment_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify assignment belongs to current user
    cursor.execute('SELECT * FROM assignments WHERE id = ? AND assigned_to = ?', 
                  (assignment_id, current_user.id))
    assignment = cursor.fetchone()
    
    if assignment and assignment['status'] == 'completed':
        cursor.execute('''
            UPDATE assignments 
            SET status = 'pending', completed_at = NULL 
            WHERE id = ?
        ''', (assignment_id,))
        
        # Optionally delete the installation that was created
        # cursor.execute('DELETE FROM installations WHERE software_id = ? AND room_id = ? AND updated_by = ? ORDER BY id DESC LIMIT 1',
        #               (assignment['software_id'], assignment['room_id'], current_user.username))
        
        conn.commit()
        flash('Assignment marked as incomplete!', 'info')
    else:
        flash('Assignment not found or not completed!', 'error')
    
    conn.close()
    return redirect(url_for('my_assignments'))

@app.route('/assignments/<int:assignment_id>/reschedule', methods=['POST'])
@login_required
def reschedule_assignment(assignment_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify assignment belongs to current user
    cursor.execute('SELECT * FROM assignments WHERE id = ? AND assigned_to = ?', 
                  (assignment_id, current_user.id))
    assignment = cursor.fetchone()
    
    if assignment:
        new_date = request.form.get('new_date')
        if new_date:
            cursor.execute('''
                UPDATE assignments 
                SET due_date = ? 
                WHERE id = ?
            ''', (new_date, assignment_id))
            
            conn.commit()
            flash('Assignment due date updated!', 'success')
        else:
            flash('Please provide a valid date!', 'error')
    else:
        flash('Assignment not found!', 'error')
    
    conn.close()
    return redirect(url_for('my_assignments'))

@app.route('/assignments/<int:assignment_id>/decline', methods=['POST'])
@login_required
def decline_assignment(assignment_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify assignment belongs to current user
    cursor.execute('SELECT * FROM assignments WHERE id = ? AND assigned_to = ?', 
                  (assignment_id, current_user.id))
    assignment = cursor.fetchone()
    
    if assignment and assignment['status'] == 'pending':
        decline_reason = request.form.get('decline_reason', '').strip()
        if decline_reason:
            cursor.execute('''
                UPDATE assignments 
                SET status = 'declined', decline_reason = ? 
                WHERE id = ?
            ''', (decline_reason, assignment_id))
            
            conn.commit()
            flash('Assignment declined!', 'info')
        else:
            flash('Please provide a reason for declining!', 'error')
    else:
        flash('Assignment not found or cannot be declined!', 'error')
    
    conn.close()
    return redirect(url_for('my_assignments'))

@app.route('/assign-installation', methods=['GET', 'POST'])
@login_required
@superuser_required
def assign_installation():
    if request.method == 'POST':
        conn = get_db()
        cursor = conn.cursor()
        
        version_ids = request.form.getlist('version_ids')
        assigned_to_ids = request.form.getlist('assigned_to_ids')
        room_ids = request.form.getlist('room_ids')
        due_date = request.form.get('due_date')
        notes = request.form.get('notes', '')
        
        assignment_count = 0
        # Create assignment for each combination of version, user, and room
        for version_id in version_ids:
            for assigned_to in assigned_to_ids:
                for room_id in room_ids:
                    cursor.execute('''
                        INSERT INTO assignments (version_id, room_id, assigned_to, assigned_by, due_date, notes)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (version_id, room_id, assigned_to, current_user.id, due_date, notes))
                    assignment_count += 1
        
        conn.commit()
        conn.close()
        
        flash(f'Created {assignment_count} assignment(s) successfully!', 'success')
        
        # Check if request came from assignments page (has referer)
        referer = request.headers.get('Referer', '')
        if 'assignments' in referer:
            return redirect(url_for('my_assignments'))
        return redirect(url_for('index'))
    
    # GET request - show assignment form
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''\n        SELECT sv.id, v.vendor_name, sp.product_name, sv.version
        FROM software_versions sv
        JOIN software_products sp ON sv.product_id = sp.id
        JOIN vendors v ON sp.vendor_id = v.id
        WHERE sv.is_latest = 1
        ORDER BY v.vendor_name, sp.product_name
    ''')
    software_list = cursor.fetchall()
    cursor.execute('SELECT id, room_name FROM rooms ORDER BY room_name')
    rooms = cursor.fetchall()
    cursor.execute('SELECT id, username, full_name FROM users ORDER BY username')
    users = cursor.fetchall()
    conn.close()
    
    return render_template('assign_installation.html', software_list=software_list, 
                          rooms=rooms, users=users)

@app.route('/download/<int:version_id>')
@login_required
def download_installer(version_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT installer_path, installer_filename FROM software_versions WHERE id = ?', (version_id,))
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

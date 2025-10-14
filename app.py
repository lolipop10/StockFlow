from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pandas as pd
from datetime import datetime
import os
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
from contextlib import contextmanager

# ==================== CONFIG ====================
app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'fallback_dev_key_only')

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==================== LOGIN ====================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ==================== DATABASE ====================
DATABASE_URL = os.environ.get('DATABASE_URL') or "sqlite:///local_inventory.db"
_db_initialized = False

@contextmanager
def get_db_connection():
    """
    Context manager for database connections with proper error handling.
    Tries sqlitecloud first, falls back to sqlite3.
    """
    conn = None
    try:
        # Try sqlitecloud if available and DATABASE_URL is set
        try:
            import sqlitecloud
            if DATABASE_URL and not DATABASE_URL.startswith('sqlite:///'):
                conn = sqlitecloud.connect(DATABASE_URL)
                yield conn
                return
        except (ImportError, Exception):
            pass

        # Fallback to sqlite3
        if DATABASE_URL.startswith('sqlite:///'):
            path = DATABASE_URL.replace('sqlite:///', '', 1)
        else:
            path = DATABASE_URL if DATABASE_URL else 'local_inventory.db'
        
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

def get_value_from_row(row, key, index=None):
    """Helper to extract value from either sqlite3.Row or tuple"""
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return row[key]
    if index is not None:
        return row[index]
    return None

# ==================== USER CLASS ====================
class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = user_id
        self.username = username
        self.role = role

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        res = c.execute("SELECT id, username, role FROM users WHERE id = ?", [user_id]).fetchone()
        if res:
            return User(
                get_value_from_row(res, 'id', 0),
                get_value_from_row(res, 'username', 1),
                get_value_from_row(res, 'role', 2)
            )
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, "is_admin", lambda: False)():
            flash('Accès refusé. Droits administrateur requis.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== UTILS ====================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_database():
    """Initialize database with all required tables"""
    global _db_initialized
    
    with get_db_connection() as conn:
        c = conn.cursor()

        # Users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                role TEXT DEFAULT 'user',
                created_at TEXT,
                created_by INTEGER,
                is_active INTEGER DEFAULT 1
            )
        ''')

        # Inventory table
        c.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                lot TEXT PRIMARY KEY,
                code_article TEXT,
                poids_physique REAL,
                remarque TEXT,
                date_scan TEXT,
                scanned_by INTEGER,
                FOREIGN KEY (scanned_by) REFERENCES users (id)
            )
        ''')

        # Config table - CREATE THIS BEFORE ANY ACCESS
        c.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        # Team members table
        c.execute('''
            CREATE TABLE IF NOT EXISTS team_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT NOT NULL,
                prenom TEXT NOT NULL,
                position TEXT NOT NULL,
                date_inventaire TEXT NOT NULL,
                created_at TEXT,
                created_by INTEGER,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')

        # Chat messages table
        c.execute('''
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER,
                message TEXT NOT NULL,
                is_group_message INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            )
        ''')

        # Create default admin if none exists
        res = c.execute("SELECT COUNT(*) as cnt FROM users WHERE role='admin'").fetchone()
        cnt = get_value_from_row(res, 'cnt', 0)
        if cnt == 0:
            password_hash = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
            c.execute(
                "INSERT INTO users (username, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, ?)",
                ['admin', password_hash, 'Administrateur', 'admin', datetime.now().isoformat()]
            )

        conn.commit()
        _db_initialized = True

def get_config(key, default=None):
    """Safely get config value with error handling"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            res = c.execute("SELECT value FROM config WHERE key=?", [key]).fetchone()
            if res:
                return get_value_from_row(res, 'value', 0)
    except Exception as e:
        # Log error but don't crash - return default
        app.logger.error(f"Error getting config for {key}: {e}")
    return default

def set_config(key, value):
    """Safely set config value"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", [key, value])
            conn.commit()
    except Exception as e:
        app.logger.error(f"Error setting config {key}: {e}")
        raise

@app.context_processor
def inject_company_info():
    """Inject company info into all templates with safe defaults"""
    return {
        'company_logo': get_config('company_logo', None),
        'company_name': get_config('company_name', 'Inventory Management')
    }

def parse_barcode(barcode):
    """Parse barcode and extract article code and lot"""
    barcode = (barcode or "").strip()
    import re
    if not re.match(r'^[A-Za-z0-9]+$', barcode):
        return "INVALID_CHARS", None
    if len(barcode) == 28:
        return barcode[8:18], barcode[18:]
    return None, None

def load_stock_data():
    """Load stock data from MB52.xlsx file"""
    try:
        df_stock = pd.read_excel('MB52.xlsx', sheet_name=0)
        if 'Lot' in df_stock.columns:
            lots_stock = df_stock['Lot'].astype(str).apply(lambda x: x.zfill(10)).tolist()
            return lots_stock, len(df_stock)
    except Exception as e:
        app.logger.warning(f"Could not load MB52.xlsx: {e}")
    return [], 0

def get_last_scan():
    """Get the most recent scan"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            res = c.execute("""
                SELECT i.lot, i.code_article, i.poids_physique, i.remarque, i.date_scan, u.username
                FROM inventory i LEFT JOIN users u ON i.scanned_by=u.id
                ORDER BY i.date_scan DESC LIMIT 1
            """).fetchone()
            
            if res:
                return {
                    'lot': get_value_from_row(res, 'lot', 0),
                    'code_article': get_value_from_row(res, 'code_article', 1),
                    'poids_physique': get_value_from_row(res, 'poids_physique', 2),
                    'remarque': get_value_from_row(res, 'remarque', 3),
                    'date_scan': get_value_from_row(res, 'date_scan', 4),
                    'scanned_by': get_value_from_row(res, 'username', 5)
                }
    except Exception as e:
        app.logger.error(f"Error getting last scan: {e}")
    return None

def get_inventory_data():
    """Get all inventory data with verification status"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            scanned = c.execute("""
                SELECT i.lot, i.code_article, i.poids_physique, i.remarque, i.date_scan, u.username
                FROM inventory i LEFT JOIN users u ON i.scanned_by=u.id
                ORDER BY i.date_scan DESC
            """).fetchall()
            
            lots_stock, _ = load_stock_data()
            result = []
            
            for row in scanned:
                lot = get_value_from_row(row, 'lot', 0)
                result.append((
                    lot,
                    get_value_from_row(row, 'code_article', 1),
                    get_value_from_row(row, 'poids_physique', 2),
                    get_value_from_row(row, 'remarque', 3),
                    get_value_from_row(row, 'date_scan', 4),
                    get_value_from_row(row, 'username', 5),
                    'OK' if lot in lots_stock else 'NOK'
                ))
            
            return result
    except Exception as e:
        app.logger.error(f"Error getting inventory data: {e}")
        return []

def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            nb = c.execute("SELECT COUNT(DISTINCT lot) as c FROM inventory").fetchone()
            nb = get_value_from_row(nb, 'c', 0) if nb else 0
            
            first = c.execute("SELECT MIN(date_scan) as f FROM inventory").fetchone()
            first = get_value_from_row(first, 'f', 0) if first else None
            
            last = c.execute("SELECT MAX(date_scan) as l FROM inventory").fetchone()
            last = get_value_from_row(last, 'l', 0) if last else None
            
            cadence = 0
            if first and last:
                try:
                    elapsed = (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds() / 3600.0
                    cadence = nb / elapsed if elapsed > 0 else 0
                except Exception:
                    cadence = 0
            
            _, cible = load_stock_data()
            
            return {
                'nb_bobines_scannees': nb,
                'cible_lot': cible,
                'cadence': round(cadence, 2),
                'first_scan_time': first,
                'last_scan_time': last
            }
    except Exception as e:
        app.logger.error(f"Error getting dashboard stats: {e}")
        return {'nb_bobines_scannees': 0, 'cible_lot': 0, 'cadence': 0, 'first_scan_time': None, 'last_scan_time': None}

def get_unread_messages_count():
    """Get count of unread messages for current user"""
    if not current_user or not getattr(current_user, "is_authenticated", False):
        return 0
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            direct = c.execute(
                "SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_id=? AND is_read=0 AND is_group_message=0",
                [current_user.id]
            ).fetchone()
            direct = get_value_from_row(direct, 'cnt', 0)
            
            group = c.execute(
                "SELECT COUNT(*) as cnt FROM chat_messages WHERE is_group_message=1 AND sender_id!=? AND is_read=0",
                [current_user.id]
            ).fetchone()
            group = get_value_from_row(group, 'cnt', 0)
            
            return int(direct) + int(group)
    except Exception as e:
        app.logger.error(f"Error getting unread messages count: {e}")
        return 0

# ==================== ROUTES ====================

# ---------- LOGIN/LOGOUT ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                res = c.execute(
                    "SELECT id, username, password_hash, role, is_active FROM users WHERE username=?",
                    [username]
                ).fetchone()
                
                if res:
                    is_active = get_value_from_row(res, 'is_active', 4)
                    pw_hash = get_value_from_row(res, 'password_hash', 2)
                    role = get_value_from_row(res, 'role', 3)
                    uid = get_value_from_row(res, 'id', 0)
                    uname = get_value_from_row(res, 'username', 1)
                    
                    if is_active and check_password_hash(pw_hash, password):
                        login_user(User(uid, uname, role))
                        flash('Connexion réussie', 'success')
                        next_page = request.args.get('next')
                        return redirect(next_page if next_page else url_for('dashboard'))
                
                flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            flash('Erreur de connexion', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Déconnecté', 'info')
    return redirect(url_for('login'))

# ---------- DASHBOARD ----------
@app.route('/')
@login_required
def dashboard():
    stats = get_dashboard_stats()
    inventory_data = get_inventory_data()
    last_scan = get_last_scan()
    unread_count = get_unread_messages_count()
    
    return render_template(
        'dashboard.html',
        stats=stats,
        inventory_data=inventory_data,
        last_scan=last_scan,
        unread_count=unread_count
    )

# ---------- SCAN ----------
@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    last_scan = get_last_scan()
    
    if request.method == 'POST':
        barcode = request.form.get('barcode', '').strip()
        poids = request.form.get('poids', 0, type=float)
        remarques = request.form.getlist('remarque')
        
        if barcode:
            code_article, lot = parse_barcode(barcode)
            
            if code_article == "INVALID_CHARS":
                flash('❌ Caractères invalides', 'error')
            elif code_article and lot:
                try:
                    with get_db_connection() as conn:
                        c = conn.cursor()
                        c.execute(
                            "INSERT INTO inventory (lot, code_article, poids_physique, remarque, date_scan, scanned_by) VALUES (?, ?, ?, ?, ?, ?)",
                            [lot, code_article, poids, ','.join(remarques), datetime.now().isoformat(), current_user.id]
                        )
                        conn.commit()
                    flash(f'✓ Lot {lot} ajouté', 'success')
                    return redirect(url_for('scan'))
                except Exception as e:
                    app.logger.error(f"Scan error: {e}")
                    flash(f'Erreur: {str(e)}', 'error')
            else:
                flash('Code-barres invalide', 'error')
    
    return render_template('scan.html', last_scan=last_scan)

# ---------- MANUAL ENTRY ----------
@app.route('/manual', methods=['GET', 'POST'])
@login_required
def manual_entry():
    if request.method == 'POST':
        lot = request.form.get('lot', '').strip()
        code_article = request.form.get('code_article', '').strip()
        poids = request.form.get('poids', 0, type=float)
        remarques = request.form.getlist('remarque')
        
        if lot and code_article:
            try:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute(
                        "INSERT INTO inventory (lot, code_article, poids_physique, remarque, date_scan, scanned_by) VALUES (?, ?, ?, ?, ?, ?)",
                        [lot, code_article, poids, ','.join(remarques), datetime.now().isoformat(), current_user.id]
                    )
                    conn.commit()
                flash(f'✓ Lot {lot} ajouté', 'success')
                return redirect(url_for('manual_entry'))
            except Exception as e:
                app.logger.error(f"Manual entry error: {e}")
                flash(f'Erreur: {str(e)}', 'error')
        else:
            flash('Veuillez entrer lot et code article', 'error')
    
    return render_template('manual.html')

# ---------- SEARCH ----------
@app.route('/search')
@login_required
def search():
    search_lot = request.args.get('lot', '').strip()
    inventory_data = get_inventory_data()
    
    if search_lot:
        filtered = [row for row in inventory_data if search_lot in row[0]]
    else:
        filtered = inventory_data
    
    return render_template('search.html', inventory_data=filtered, search_lot=search_lot)

# ---------- EXPORT ----------
@app.route('/export', methods=['POST'])
@login_required
@admin_required
def export_data():
    data = get_inventory_data()
    df = pd.DataFrame(data, columns=["Lot", "Code Article", "Poids Physique", "Remarque", "Date Scan", "Scanné par", "Vérification"])
    
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='inventory')
    output.seek(0)
    
    filename = f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

# ---------- RESET ----------
@app.route('/reset', methods=['GET', 'POST'])
@login_required
@admin_required
def reset_inventory():
    if request.method == 'POST':
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("DELETE FROM inventory")
                conn.commit()
            flash('Inventaire réinitialisé', 'success')
        except Exception as e:
            app.logger.error(f"Reset error: {e}")
            flash(f'Erreur: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('reset.html')

# ---------- USERS CRUD ----------
@app.route('/users')
@login_required
@admin_required
def users():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            users_list = c.execute(
                "SELECT id, username, full_name, role, created_at, is_active FROM users ORDER BY created_at DESC"
            ).fetchall()
    except Exception as e:
        app.logger.error(f"Users list error: {e}")
        users_list = []
    
    return render_template('users.html', users=users_list)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '')
        fn = request.form.get('full_name', '').strip()
        r = request.form.get('role', 'user')
        
        if u and p:
            try:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute(
                        "INSERT INTO users (username, password_hash, full_name, role, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                        [u, generate_password_hash(p), fn, r, datetime.now().isoformat(), current_user.id]
                    )
                    conn.commit()
                flash('Utilisateur créé', 'success')
                return redirect(url_for('users'))
            except Exception as e:
                app.logger.error(f"Create user error: {e}")
                flash(f'Erreur: {str(e)}', 'error')
        else:
            flash('Champs requis', 'error')
    
    return render_template('create_user.html')

@app.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    if user_id == current_user.id:
        flash('Impossible de désactiver votre compte', 'error')
        return redirect(url_for('users'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET is_active = 1 - is_active WHERE id = ?", [user_id])
            conn.commit()
        flash('Statut mis à jour', 'success')
    except Exception as e:
        app.logger.error(f"Toggle user error: {e}")
        flash(f'Erreur: {str(e)}', 'error')
    
    return redirect(url_for('users'))

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('Impossible de supprimer votre compte', 'error')
        return redirect(url_for('users'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE id = ?", [user_id])
            conn.commit()
        flash('Utilisateur supprimé', 'success')
    except Exception as e:
        app.logger.error(f"Delete user error: {e}")
        flash(f'Erreur: {str(e)}', 'error')
    
    return redirect(url_for('users'))

# ---------- CHAT ----------
@app.route('/chat')
@login_required
def chat():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            users_list = c.execute(
                "SELECT id, username, full_name FROM users WHERE id != ? AND is_active = 1 ORDER BY username",
                [current_user.id]
            ).fetchall()
    except Exception as e:
        app.logger.error(f"Chat users list error: {e}")
        users_list = []
    
    return render_template('chat.html', users=users_list)

@app.route('/chat/messages')
@login_required
def chat_messages():
    chat_type = request.args.get('type', 'direct')
    other_id = request.args.get('user_id', type=int)

    try:
        with get_db_connection() as conn:
            c = conn.cursor()

            if chat_type == 'group':
                messages = c.execute("""
                    SELECT cm.id, cm.sender_id, u.username, u.full_name, cm.message, cm.created_at, cm.is_read
                    FROM chat_messages cm
                    JOIN users u ON cm.sender_id = u.id
                    WHERE cm.is_group_message = 1
                    ORDER BY cm.created_at DESC
                    LIMIT 100
                """).fetchall()

                c.execute(
                    "UPDATE chat_messages SET is_read = 1 WHERE is_group_message = 1 AND sender_id != ?",
                    [current_user.id]
                )

            elif chat_type == 'direct':
                if not other_id:
                    return jsonify({'error': 'user_id requis pour chat direct'}), 400

                messages = c.execute("""
                    SELECT cm.id, cm.sender_id, u.username, u.full_name, cm.message, cm.created_at, cm.is_read
                    FROM chat_messages cm
                    JOIN users u ON cm.sender_id = u.id
                    WHERE cm.is_group_message = 0
                      AND ((cm.sender_id = ? AND cm.receiver_id = ?) OR (cm.sender_id = ? AND cm.receiver_id = ?))
                    ORDER BY cm.created_at DESC
                    LIMIT 100
                """, [current_user.id, other_id, other_id, current_user.id]).fetchall()

                c.execute(
                    "UPDATE chat_messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_read = 0",
                    [current_user.id, other_id]
                )
            else:
                return jsonify({'error': 'type de chat inconnu'}), 400

            conn.commit()

            msgs = []
            for m in messages:
                msgs.append({
                    'id': get_value_from_row(m, 'id', 0),
                    'sender_id': get_value_from_row(m, 'sender_id', 1),
                    'sender_username': get_value_from_row(m, 'username', 2),
                    'sender_fullname': get_value_from_row(m, 'full_name', 3),
                    'message': get_value_from_row(m, 'message', 4),
                    'created_at': get_value_from_row(m, 'created_at', 5),
                    'is_read': bool(get_value_from_row(m, 'is_read', 6)),
                    'is_own': (get_value_from_row(m, 'sender_id', 1) == current_user.id)
                })

            return jsonify({'messages': list(reversed(msgs))})
    except Exception as e:
        app.logger.error(f"Chat messages error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/chat/unread_count')
@login_required
def chat_unread_count():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            direct = c.execute(
                "SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_id = ? AND is_read = 0 AND is_group_message = 0",
                [current_user.id]
            ).fetchone()
            direct = get_value_from_row(direct, 'cnt', 0)

            group = c.execute(
                "SELECT COUNT(*) as cnt FROM chat_messages WHERE is_group_message = 1 AND sender_id != ? AND is_read = 0",
                [current_user.id]
            ).fetchone()
            group = get_value_from_row(group, 'cnt', 0)

            users = c.execute("""
                SELECT cm.sender_id, u.username, COUNT(*) as count
                FROM chat_messages cm
                JOIN users u ON cm.sender_id = u.id
                WHERE cm.receiver_id = ? AND cm.is_read = 0 AND cm.is_group_message = 0
                GROUP BY cm.sender_id, u.username
            """, [current_user.id]).fetchall()

            unread_by_user = {}
            for row in users:
                sid = get_value_from_row(row, 'sender_id', 0)
                uname = get_value_from_row(row, 'username', 1)
                cnt = get_value_from_row(row, 'count', 2)
                unread_by_user[sid] = {'username': uname, 'count': cnt}

            return jsonify({
                'count': int(direct) + int(group),
                'direct': int(direct),
                'group': int(group),
                'by_user': unread_by_user
            })
    except Exception as e:
        app.logger.error(f"Unread count error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/chat/send', methods=['POST'])
@login_required
def chat_send():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'error': 'JSON invalide'}), 400

    msg = (data.get('message') or '').strip()
    ctype = data.get('type', 'direct')
    rid = data.get('receiver_id', None)

    if not msg:
        return jsonify({'error': 'Message vide'}), 400

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            if ctype == 'group':
                c.execute(
                    "INSERT INTO chat_messages (sender_id, message, is_group_message, created_at) VALUES (?, ?, 1, ?)",
                    [current_user.id, msg, datetime.now().isoformat()]
                )
            else:
                if not rid:
                    return jsonify({'error': 'Destinataire requis pour chat direct'}), 400
                c.execute(
                    "INSERT INTO chat_messages (sender_id, receiver_id, message, is_group_message, created_at) VALUES (?, ?, ?, 0, ?)",
                    [current_user.id, rid, msg, datetime.now().isoformat()]
                )
            
            conn.commit()
            mid = c.lastrowid
            
        return jsonify({'success': True, 'message_id': mid, 'created_at': datetime.now().isoformat()})
    except Exception as e:
        app.logger.error(f"Chat send error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/chat/mark_all_read', methods=['POST'])
@login_required
def mark_all_read():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'error': 'JSON invalide'}), 400

    chat_type = data.get('type', 'direct')
    user_id = data.get('user_id')

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            if chat_type == 'group':
                c.execute(
                    "UPDATE chat_messages SET is_read = 1 WHERE is_group_message = 1 AND sender_id != ?",
                    [current_user.id]
                )
            elif chat_type == 'direct' and user_id:
                c.execute(
                    "UPDATE chat_messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_group_message = 0",
                    [current_user.id, user_id]
                )
            else:
                return jsonify({'error': 'Paramètres invalides pour mark_all_read'}), 400

            conn.commit()
            
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Mark all read error: {e}")
        return jsonify({'error': str(e)}), 500

# ---------- SETTINGS ----------
@app.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    if request.method == 'POST':
        name = (request.form.get('company_name') or '').strip()
        
        if name:
            try:
                set_config('company_name', name)
                flash('Nom de l\'entreprise mis à jour', 'success')
            except Exception as e:
                app.logger.error(f"Settings update error: {e}")
                flash(f'Erreur: {str(e)}', 'error')

        return redirect(url_for('settings'))

    current_name = get_config('company_name', 'Inventory Management')
    return render_template('settings.html', company_name=current_name)

# ---------- PROFILE ----------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        cp = request.form.get('current_password', '')
        npw = request.form.get('new_password', '')
        cf = request.form.get('confirm_password', '')
        
        if npw != cf:
            flash('Les mots de passe ne correspondent pas', 'error')
        else:
            try:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    res = c.execute("SELECT password_hash FROM users WHERE id = ?", [current_user.id]).fetchone()
                    
                    if res:
                        pw_hash = get_value_from_row(res, 'password_hash', 0)
                        if check_password_hash(pw_hash, cp):
                            c.execute(
                                "UPDATE users SET password_hash = ? WHERE id = ?",
                                [generate_password_hash(npw), current_user.id]
                            )
                            conn.commit()
                            flash('Mot de passe modifié', 'success')
                        else:
                            flash('Mot de passe actuel incorrect', 'error')
            except Exception as e:
                app.logger.error(f"Profile update error: {e}")
                flash(f'Erreur: {str(e)}', 'error')
    
    return render_template('profile.html')

# ---------- UPDATE WEIGHTS ----------
@app.route('/update_weights', methods=['POST'])
@login_required
@admin_required
def update_weights():
    try:
        df = pd.read_excel('MB52.xlsx')
        if 'Lot' in df.columns and 'Poids' in df.columns:
            df['Lot'] = df['Lot'].astype(str).apply(lambda x: x.zfill(10))
            
            with get_db_connection() as conn:
                c = conn.cursor()
                updated = 0
                for _, row in df.iterrows():
                    try:
                        c.execute("UPDATE inventory SET poids_physique = ? WHERE lot = ?", [row['Poids'], row['Lot']])
                        updated += 1
                    except Exception:
                        continue
                conn.commit()
            
            flash(f'Poids mis à jour ({updated} lots)', 'success')
        else:
            flash('Fichier MB52.xlsx invalide (colonnes Lot/Poids manquantes)', 'error')
    except Exception as e:
        app.logger.error(f"Update weights error: {e}")
        flash(f'Erreur: {str(e)}', 'error')
    
    return redirect(url_for('search'))

# ---------- HEALTH CHECK ----------
@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT 1").fetchone()
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f"Internal error: {e}")
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {e}")
    if request.path.startswith('/api/') or request.path.startswith('/chat/'):
        return jsonify({'error': 'Une erreur est survenue'}), 500
    flash('Une erreur est survenue', 'error')
    return redirect(url_for('dashboard'))

# ==================== MAIN ====================
if __name__ == '__main__':
    # Initialize database before starting app
    init_database()
    
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run app
    app.run(host='0.0.0.0', port=port, debug=False)

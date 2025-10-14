

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pandas as pd
# note: sqlitecloud may be optional in some deployments; we try-import inside get_db_connection
from dotenv import load_dotenv
load_dotenv()  # Charge les variables depuis .env
from datetime import datetime
import os
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3

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
DATABASE_URL = os.environ.get('DATABASE_URL')
SQLITECLOUD_URL = os.environ.get('SQLITECLOUD_URL')
def get_db_connection():
    """
    Essaie sqlitecloud.connect si disponible et si DATABASE_URL n'est pas vide,
    sinon se rabat sur sqlite3. Gère 'sqlite:///' prefix correctement.
    Retourne une connexion DB compatible cursor().
    """
    # tentative sqlitecloud si installé
    try:
        import sqlitecloud  # import local pour ne pas planter si non installé
        # sqlitecloud.connect peut accepter différents formats
        try:
            return sqlitecloud.connect(DATABASE_URL)
        except Exception:
            pass
    except Exception:
        # sqlitecloud non installé -> on continue vers sqlite3
        pass

    # fallback sqlite3
    if DATABASE_URL.startswith('sqlite:///'):
        path = DATABASE_URL.replace('sqlite:///', '', 1)
    else:
        path = DATABASE_URL
    # si path vide -> utiliser local path
    if not path:
        path = 'local_inventory.db'
    # s'assurer du dossier parent
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    # utiliser row factory pour accès par nom si besoin
    conn.row_factory = sqlite3.Row
    return conn

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
    conn = get_db_connection()
    c = conn.cursor()
    res = c.execute("SELECT id, username, role FROM users WHERE id = ?", [user_id]).fetchone()
    conn.close()
    if res:
        return User(res['id'] if isinstance(res, sqlite3.Row) else res[0],
                    res['username'] if isinstance(res, sqlite3.Row) else res[1],
                    res['role'] if isinstance(res, sqlite3.Row) else res[2])
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
    conn = get_db_connection()
    c = conn.cursor()

    # users table
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

    # inventory table
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

    # config table
    c.execute('''
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    # team_members table
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

    # chat_messages table
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

    # default admin
    res = c.execute("SELECT COUNT(*) as cnt FROM users WHERE role='admin'").fetchone()
    cnt = res['cnt'] if isinstance(res, sqlite3.Row) else res[0]
    if cnt == 0:
        password_hash = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
        c.execute("INSERT INTO users (username, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, ?)",
                  ['admin', password_hash, 'Administrateur', 'admin', datetime.now().isoformat()])

    conn.commit()
    conn.close()

def get_config(key, default=None):
    conn = get_db_connection()
    c = conn.cursor()
    res = c.execute("SELECT value FROM config WHERE key=?", [key]).fetchone()
    conn.close()
    if res:
        return res['value'] if isinstance(res, sqlite3.Row) else res[0]
    return default

def set_config(key, value):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO config (key,value) VALUES (?,?)", [key, value])
    conn.commit()
    conn.close()

@app.context_processor
def inject_company_info():
    return {
        'company_logo': get_config('company_logo', None),
        'company_name': get_config('company_name', 'Inventory Management')
    }

def parse_barcode(barcode):
    """
    Exemple simple : vérifie caractères alphanumériques, si longueur 28 découpe.
    Retour: (code_article, lot) ou ("INVALID_CHARS", None) ou (None,None)
    """
    barcode = (barcode or "").strip()
    import re
    if not re.match(r'^[A-Za-z0-9]+$', barcode):
        return "INVALID_CHARS", None
    if len(barcode) == 28:
        return barcode[8:18], barcode[18:]
    return None, None

def load_stock_data():
    """
    Charge MB52.xlsx si présent et renvoie la liste des lots (zfill 10) + count.
    Silencieux en cas d'erreur -> ([], 0)
    """
    try:
        df_stock = pd.read_excel('MB52.xlsx', sheet_name=0)
        if 'Lot' in df_stock.columns:
            lots_stock = df_stock['Lot'].astype(str).apply(lambda x: x.zfill(10)).tolist()
            return lots_stock, len(df_stock)
    except Exception:
        pass
    return [], 0

def get_last_scan():
    conn = get_db_connection()
    c = conn.cursor()
    res = c.execute("""
        SELECT i.lot, i.code_article, i.poids_physique, i.remarque, i.date_scan, u.username
        FROM inventory i LEFT JOIN users u ON i.scanned_by=u.id
        ORDER BY i.date_scan DESC LIMIT 1
    """).fetchone()
    conn.close()
    if res:
        if isinstance(res, sqlite3.Row):
            return {'lot': res['lot'], 'code_article': res['code_article'], 'poids_physique': res['poids_physique'],
                    'remarque': res['remarque'], 'date_scan': res['date_scan'], 'scanned_by': res['username']}
        else:
            return {'lot': res[0], 'code_article': res[1], 'poids_physique': res[2],
                    'remarque': res[3], 'date_scan': res[4], 'scanned_by': res[5]}
    return None

def get_inventory_data():
    conn = get_db_connection()
    c = conn.cursor()
    scanned = c.execute("""
        SELECT i.lot,i.code_article,i.poids_physique,i.remarque,i.date_scan,u.username
        FROM inventory i LEFT JOIN users u ON i.scanned_by=u.id
    """).fetchall()
    conn.close()
    lots_stock, _ = load_stock_data()
    result = []
    for row in scanned:
        if isinstance(row, sqlite3.Row):
            lot = row['lot']
            tup = (row['lot'], row['code_article'], row['poids_physique'], row['remarque'], row['date_scan'], row['username'],
                   ('OK' if lot in lots_stock else 'NOK'))
        else:
            lot = row[0]
            tup = (row[0], row[1], row[2], row[3], row[4], row[5], ('OK' if lot in lots_stock else 'NOK'))
        result.append(tup)
    return result

def get_dashboard_stats():
    conn = get_db_connection()
    c = conn.cursor()
    nb = c.execute("SELECT COUNT(DISTINCT lot) as c FROM inventory").fetchone()
    nb = (nb['c'] if isinstance(nb, sqlite3.Row) else nb[0]) if nb else 0
    first = c.execute("SELECT MIN(date_scan) as f FROM inventory").fetchone()
    first = (first['f'] if isinstance(first, sqlite3.Row) else first[0]) if first else None
    last = c.execute("SELECT MAX(date_scan) as l FROM inventory").fetchone()
    last = (last['l'] if isinstance(last, sqlite3.Row) else last[0]) if last else None
    cadence = 0
    if first and last:
        try:
            elapsed = (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds() / 3600.0
            cadence = nb / elapsed if elapsed > 0 else 0
        except Exception:
            cadence = 0
    conn.close()
    _, cible = load_stock_data()
    return {'nb_bobines_scannees': nb, 'cible_lot': cible, 'cadence': round(cadence, 2),
            'first_scan_time': first, 'last_scan_time': last}

def get_unread_messages_count():
    """
    Retourne le nombre total de messages non lus pour l'utilisateur courant.
    """
    if not current_user or not getattr(current_user, "is_authenticated", False):
        return 0
    conn = get_db_connection()
    c = conn.cursor()
    try:
        direct = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_id=? AND is_read=0 AND is_group_message=0",
            [current_user.id]
        ).fetchone()
        direct = direct['cnt'] if isinstance(direct, sqlite3.Row) else direct[0]
        group = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE is_group_message=1 AND sender_id!=? AND is_read=0",
            [current_user.id]
        ).fetchone()
        group = group['cnt'] if isinstance(group, sqlite3.Row) else group[0]
        return int(direct) + int(group)
    except Exception:
        return 0
    finally:
        try:
            conn.close()
        except:
            pass

# ==================== ROUTES ====================

# ---------- LOGIN/LOGOUT ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = get_db_connection(); c = conn.cursor()
        res = c.execute("SELECT id,username,password_hash,role,is_active FROM users WHERE username=?",[username]).fetchone()
        conn.close()
        if res:
            is_active = res['is_active'] if isinstance(res, sqlite3.Row) else res[4]
            pw_hash = res['password_hash'] if isinstance(res, sqlite3.Row) else res[2]
            role = res['role'] if isinstance(res, sqlite3.Row) else res[3]
            uid = res['id'] if isinstance(res, sqlite3.Row) else res[0]
            uname = res['username'] if isinstance(res, sqlite3.Row) else res[1]
            if is_active and check_password_hash(pw_hash, password):
                login_user(User(uid, uname, role))
                flash('Connexion réussie','success')
                return redirect(url_for('dashboard'))
        flash('Nom d’utilisateur ou mot de passe incorrect','error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Déconnecté','info')
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
@app.route('/scan', methods=['GET','POST'])
@login_required
def scan():
    last_scan = get_last_scan()
    if request.method == 'POST':
        barcode = request.form.get('barcode','').strip()
        poids = request.form.get('poids', 0, type=float)
        remarques = request.form.getlist('remarque')
        if barcode:
            code_article, lot = parse_barcode(barcode)
            if code_article == "INVALID_CHARS":
                flash('❌ Caractères invalides','error')
                return render_template('scan.html', last_scan=last_scan)
            elif code_article and lot:
                try:
                    conn = get_db_connection(); c = conn.cursor()
                    c.execute("INSERT INTO inventory (lot,code_article,poids_physique,remarque,date_scan,scanned_by) VALUES (?,?,?,?,?,?)",
                              [lot, code_article, poids, ','.join(remarques), datetime.now().isoformat(), current_user.id])
                    conn.commit(); conn.close()
                    flash(f'✓ Lot {lot} ajouté','success')
                    return redirect(url_for('scan'))
                except Exception as e:
                    flash('Erreur: ' + str(e), 'error')
            else:
                flash('Code-barres invalide','error')
    return render_template('scan.html', last_scan=last_scan)

# ---------- MANUAL ENTRY ----------
@app.route('/manual', methods=['GET','POST'])
@login_required
def manual_entry():
    if request.method == 'POST':
        lot = request.form.get('lot','').strip()
        code_article = request.form.get('code_article','').strip()
        poids = request.form.get('poids', 0, type=float)
        remarques = request.form.getlist('remarque')
        if lot and code_article:
            try:
                conn = get_db_connection(); c = conn.cursor()
                c.execute("INSERT INTO inventory (lot,code_article,poids_physique,remarque,date_scan,scanned_by) VALUES (?,?,?,?,?,?)",
                          [lot, code_article, poids, ','.join(remarques), datetime.now().isoformat(), current_user.id])
                conn.commit(); conn.close()
                flash(f'✓ Lot {lot} ajouté','success')
                return redirect(url_for('manual_entry'))
            except Exception as e:
                flash('Erreur: ' + str(e), 'error')
        else:
            flash('Veuillez entrer lot et code article','error')
    return render_template('manual.html')

# ---------- SEARCH ----------
@app.route('/search')
@login_required
def search():
    search_lot = request.args.get('lot','').strip()
    inventory_data = get_inventory_data()
    filtered = [row for row in inventory_data if search_lot in row[0]] if search_lot else inventory_data
    return render_template('search.html', inventory_data=filtered, search_lot=search_lot)

# ---------- EXPORT ----------
@app.route('/export', methods=['POST'])
@login_required
@admin_required
def export_data():
    # get_inventory_data returns tuples: (Lot,Code Article,Poids Physique,Remarque,Date Scan,Scanné par,Vérification)
    data = get_inventory_data()
    df = pd.DataFrame(data, columns=["Lot","Code Article","Poids Physique","Remarque","Date Scan","Scanné par","Vérification"])
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='inventory')
    output.seek(0)
    filename = f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(output, as_attachment=True, download_name=filename,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# ---------- RESET ----------
@app.route('/reset', methods=['GET','POST'])
@login_required
@admin_required
def reset_inventory():
    if request.method == 'POST':
        conn = get_db_connection(); c = conn.cursor()
        c.execute("DELETE FROM inventory"); conn.commit(); conn.close()
        flash('Inventaire réinitialisé','success')
        return redirect(url_for('dashboard'))
    return render_template('reset.html')

# ---------- USERS CRUD ----------
@app.route('/users')
@login_required
@admin_required
def users():
    conn = get_db_connection(); c = conn.cursor()
    users_list = c.execute("SELECT id,username,full_name,role,created_at,is_active FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('users.html', users=users_list)

@app.route('/users/create', methods=['GET','POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        fn = request.form.get('full_name','').strip()
        r = request.form.get('role','user')
        if u and p:
            try:
                conn = get_db_connection(); c = conn.cursor()
                c.execute("INSERT INTO users (username,password_hash,full_name,role,created_at,created_by) VALUES (?,?,?,?,?,?)",
                          [u, generate_password_hash(p), fn, r, datetime.now().isoformat(), current_user.id])
                conn.commit(); conn.close()
                flash('Utilisateur créé','success')
                return redirect(url_for('users'))
            except Exception as e:
                flash('Erreur: ' + str(e), 'error')
        else:
            flash('Champs requis','error')
    return render_template('create_user.html')

@app.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    if user_id == current_user.id:
        flash('Impossible de désactiver votre compte','error')
        return redirect(url_for('users'))
    conn = get_db_connection(); c = conn.cursor()
    c.execute("UPDATE users SET is_active=1-is_active WHERE id=?", [user_id]); conn.commit(); conn.close()
    flash('Statut mis à jour','success')
    return redirect(url_for('users'))

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('Impossible de supprimer votre compte','error')
        return redirect(url_for('users'))
    conn = get_db_connection(); c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", [user_id]); conn.commit(); conn.close()
    flash('Utilisateur supprimé','success')
    return redirect(url_for('users'))

# ---------- CHAT ----------
@app.route('/chat')
@login_required
def chat():
    conn = get_db_connection(); c = conn.cursor()
    users_list = c.execute(
        "SELECT id,username,full_name FROM users WHERE id!=? AND is_active=1 ORDER BY username",
        [current_user.id]
    ).fetchall()
    conn.close()
    return render_template('chat.html', users=users_list)

@app.route('/chat/messages')
@login_required
def chat_messages():
    """
    Récupère les 100 derniers messages pour le type de chat demandé.
    Query params:
      - type: 'direct' (default) ou 'group'
      - user_id: id de l'autre utilisateur pour 'direct'
    """
    chat_type = request.args.get('type', 'direct')
    other_id = request.args.get('user_id', type=int)

    conn = get_db_connection()
    c = conn.cursor()

    try:
        if chat_type == 'group':
            messages = c.execute(
                """SELECT cm.id, cm.sender_id, u.username, u.full_name, cm.message, cm.created_at, cm.is_read
                   FROM chat_messages cm
                   JOIN users u ON cm.sender_id = u.id
                   WHERE cm.is_group_message=1
                   ORDER BY cm.created_at DESC
                   LIMIT 100"""
            ).fetchall()

            c.execute(
                "UPDATE chat_messages SET is_read=1 WHERE is_group_message=1 AND sender_id!=?",
                [current_user.id]
            )

        elif chat_type == 'direct':
            if not other_id:
                conn.close()
                return jsonify({'error': 'user_id requis pour chat direct'}), 400

            messages = c.execute(
                """SELECT cm.id, cm.sender_id, u.username, u.full_name, cm.message, cm.created_at, cm.is_read
                   FROM chat_messages cm
                   JOIN users u ON cm.sender_id = u.id
                   WHERE cm.is_group_message=0
                     AND ((cm.sender_id=? AND cm.receiver_id=?) OR (cm.sender_id=? AND cm.receiver_id=?))
                   ORDER BY cm.created_at DESC
                   LIMIT 100""",
                [current_user.id, other_id, other_id, current_user.id]
            ).fetchall()

            c.execute(
                "UPDATE chat_messages SET is_read=1 WHERE receiver_id=? AND sender_id=? AND is_read=0",
                [current_user.id, other_id]
            )
        else:
            conn.close()
            return jsonify({'error': 'type de chat inconnu'}), 400

        conn.commit()

        msgs = []
        for m in messages:
            if isinstance(m, sqlite3.Row):
                sender_id = m['sender_id']; sender_username = m['username']; sender_fullname = m['full_name']
                created_at = m['created_at']; is_read = bool(m['is_read']); mid = m['id']; message = m['message']
            else:
                sender_id = m[1]; sender_username = m[2]; sender_fullname = m[3]
                message = m[4]; created_at = m[5]; is_read = bool(m[6]); mid = m[0]

            msgs.append({
                'id': mid,
                'sender_id': sender_id,
                'sender_username': sender_username,
                'sender_fullname': sender_fullname,
                'message': message,
                'created_at': created_at,
                'is_read': is_read,
                'is_own': (sender_id == current_user.id)
            })

        conn.close()
        # renvoyer en ordre chronologique asc
        return jsonify({'messages': list(reversed(msgs))})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/chat/unread_count')
@login_required
def chat_unread_count():
    conn = get_db_connection(); c = conn.cursor()
    try:
        direct = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_id=? AND is_read=0 AND is_group_message=0",
            [current_user.id]
        ).fetchone()
        direct = direct['cnt'] if isinstance(direct, sqlite3.Row) else direct[0]

        group = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE is_group_message=1 AND sender_id!=? AND is_read=0",
            [current_user.id]
        ).fetchone()
        group = group['cnt'] if isinstance(group, sqlite3.Row) else group[0]

        users = c.execute(
            """SELECT cm.sender_id, u.username, COUNT(*) as count
               FROM chat_messages cm
               JOIN users u ON cm.sender_id = u.id
               WHERE cm.receiver_id=? AND cm.is_read=0 AND cm.is_group_message=0
               GROUP BY cm.sender_id, u.username""",
            [current_user.id]
        ).fetchall()

        unread_by_user = {}
        for row in users:
            if isinstance(row, sqlite3.Row):
                sid = row['sender_id']; uname = row['username']; cnt = row['count']
            else:
                sid = row[0]; uname = row[1]; cnt = row[2]
            unread_by_user[sid] = {'username': uname, 'count': cnt}

        return jsonify({
            'count': int(direct) + int(group),
            'direct': int(direct),
            'group': int(group),
            'by_user': unread_by_user
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            conn.close()
        except:
            pass

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

    conn = get_db_connection(); c = conn.cursor()
    try:
        if ctype == 'group':
            c.execute(
                "INSERT INTO chat_messages (sender_id, message, is_group_message, created_at) VALUES (?, ?, 1, ?)",
                [current_user.id, msg, datetime.now().isoformat()]
            )
        else:
            if not rid:
                conn.close()
                return jsonify({'error': 'Destinataire requis pour chat direct'}), 400
            c.execute(
                "INSERT INTO chat_messages (sender_id, receiver_id, message, is_group_message, created_at) VALUES (?, ?, ?, 0, ?)",
                [current_user.id, rid, msg, datetime.now().isoformat()]
            )
        conn.commit()
        mid = c.lastrowid
        conn.close()
        return jsonify({'success': True, 'message_id': mid, 'created_at': datetime.now().isoformat()})
    except Exception as e:
        conn.close()
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

    conn = get_db_connection(); c = conn.cursor()
    try:
        if chat_type == 'group':
            c.execute("UPDATE chat_messages SET is_read=1 WHERE is_group_message=1 AND sender_id!=?", [current_user.id])
        elif chat_type == 'direct' and user_id:
            c.execute("UPDATE chat_messages SET is_read=1 WHERE receiver_id=? AND sender_id=? AND is_group_message=0", [current_user.id, user_id])
        else:
            conn.close()
            return jsonify({'error': 'Paramètres invalides pour mark_all_read'}), 400

        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

# ---------- SETTINGS (company name & logo) ----------
@app.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    if request.method == 'POST':
        name = (request.form.get('company_name') or '').strip()
        # logo = request.files.get('company_logo')

        # update company name if provided
        if name:
            set_config('company_name', name)
            flash('Nom de l\'entreprise mis à jour', 'success')

        

        return redirect(url_for('settings'))

    # GET -> afficher paramètres actuels
    current_name = get_config('company_name', 'Inventory Management')
    # current_logo = get_config('company_logo', None)
    return render_template('settings.html', company_name=current_name)

# ---------- PROFILE ----------
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    if request.method == 'POST':
        cp = request.form.get('current_password','')
        npw = request.form.get('new_password','')
        cf = request.form.get('confirm_password','')
        if npw != cf:
            flash('Les mots de passe ne correspondent pas','error')
        else:
            conn = get_db_connection(); c = conn.cursor()
            res = c.execute("SELECT password_hash FROM users WHERE id=?", [current_user.id]).fetchone()
            if res:
                pw_hash = res['password_hash'] if isinstance(res, sqlite3.Row) else res[0]
                if check_password_hash(pw_hash, cp):
                    c.execute("UPDATE users SET password_hash=? WHERE id=?", [generate_password_hash(npw), current_user.id])
                    conn.commit()
                    flash('Mot de passe modifié','success')
                else:
                    flash('Mot de passe actuel incorrect','error')
            conn.close()
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
            conn = get_db_connection(); c = conn.cursor()
            for _, row in df.iterrows():
                try:
                    c.execute("UPDATE inventory SET poids_physique=? WHERE lot=?", [row['Poids'], row['Lot']])
                except Exception:
                    # ignorer ligne si problème pour ne pas bloquer tout le processus
                    continue
            conn.commit(); conn.close()
            flash('Poids mis à jour','success')
        else:
            flash('Fichier MB52.xlsx invalide (colonnes Lot/Poids manquantes)', 'error')
    except Exception as e:
        flash('Erreur: ' + str(e), 'error')
    return redirect(url_for('search'))

# ==================== MAIN ====================
if __name__ == "__main__":
    with app.app_context():
        init_database()  # crée toutes les tables dans SQLiteCloud
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

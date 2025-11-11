from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pandas as pd
from datetime import datetime
import os
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlitecloud

# ==================== CONFIG ====================
app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'fallback_dev_key_only')
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==================== SQLITECLOUD CONNECTION ====================
SQLITECLOUD_CONNECTION_STRING = "sqlitecloud://cpvyytm4hk.g2.sqlite.cloud:8860/inventory_12.db?apikey=9aagFJ25p8vWwwSkINdfvhGqkncYJmBCcz44ttVrZXg"

def get_db_connection():
    """Connexion à SQLiteCloud"""
    conn = sqlitecloud.connect(SQLITECLOUD_CONNECTION_STRING)
    # SQLiteCloud supporte row_factory pour compatibilité avec sqlite3
    conn.row_factory = sqlitecloud.Row
    return conn

# ==================== LOGIN ====================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Test de connexion au démarrage
try:
    test_conn = get_db_connection()
    print("✅ SQLiteCloud Connection OK")
    test_conn.close()
except Exception as e:
    print(f"❌ SQLiteCloud Connection Error: {e}")

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
    try:
        c = conn.cursor()
        res = c.execute("SELECT id, username, role FROM users WHERE id = ?", [user_id]).fetchone()
        if res:
            return User(res['id'], res['username'], res['role'])
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


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
    """Initialisation de la base de données sur SQLiteCloud"""
    conn = get_db_connection()
    try:
        c = conn.cursor()

        # Table des utilisateurs
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

        # Table d'inventaire
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

        # Table de configuration
        c.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        # Table des membres d'équipe
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

        # Table des messages
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

        # Table de contrôle qualité
        c.execute('''
            CREATE TABLE IF NOT EXISTS quality_control (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lot TEXT NOT NULL UNIQUE,
                code_article TEXT,
                statut_qualite TEXT NOT NULL CHECK(statut_qualite IN ('CONFORME', 'NON_CONFORME', 'EN_ATTENTE')),
                non_conformite TEXT,
                decision_finale TEXT CHECK(decision_finale IN ('A_LIVRER', 'A_TRANSFORMER', 'A_RECYCLER', 'MAGASIN_NC', NULL)),
                controleur_id INTEGER,
                controleur_nom TEXT,
                date_controle TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date_modification TIMESTAMP,
                FOREIGN KEY (controleur_id) REFERENCES users(id)
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS quality_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lot TEXT NOT NULL,
                ancien_statut TEXT,
                nouveau_statut TEXT,
                ancienne_decision TEXT,
                nouvelle_decision TEXT,
                commentaire TEXT,
                modifie_par TEXT,
                date_modification TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Indices
        try:
            c.execute("CREATE INDEX IF NOT EXISTS idx_quality_lot ON quality_control(lot)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_quality_statut ON quality_control(statut_qualite)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_quality_decision ON quality_control(decision_finale)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_history_lot ON quality_history(lot)")
        except Exception as e:
            print(f"⚠️  Indices: {e}")

        # Création d'un admin par défaut si aucun n'existe
        res = c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()
        cnt = res[0] if res else 0
        if cnt == 0:
            password_hash = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
            c.execute('''
                INSERT INTO users (username, password_hash, full_name, role, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', password_hash, 'Administrateur', 'admin', datetime.now().isoformat()))

        conn.commit()
        print("✅ Database initialized successfully on SQLiteCloud")

    except Exception as e:
        print(f"❌ Erreur lors de l'initialisation de la base : {e}")
        conn.rollback()

    finally:
        conn.close()


def get_config(key, default=None):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        res = c.execute("SELECT value FROM config WHERE key=?", [key]).fetchone()
        return res['value'] if res else default
    finally:
        try:
            conn.close()
        except Exception:
            pass


def set_config(key, value):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO config (key,value) VALUES (?,?)", [key, value])
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.context_processor
def inject_company_info():
    return {
        'company_logo': get_config('company_logo', None),
        'company_name': get_config('company_name', 'Inventory Management')
    }


def parse_barcode(barcode):
    """
    Simple barcode parsing example.
    Returns (code_article, lot) or ("INVALID_CHARS", None) or (None, None)
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
    Load MB52.xlsx if present and return lots (zfilled) + count.
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
    try:
        c = conn.cursor()
        res = c.execute("""
            SELECT i.lot, i.code_article, i.poids_physique, i.remarque, i.date_scan, u.username
            FROM inventory i LEFT JOIN users u ON i.scanned_by=u.id
            ORDER BY i.date_scan DESC LIMIT 1
        """).fetchone()
        if res:
            return {'lot': res['lot'], 'code_article': res['code_article'], 'poids_physique': res['poids_physique'],
                    'remarque': res['remarque'], 'date_scan': res['date_scan'], 'scanned_by': res['username']}
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_inventory_data():
    conn = get_db_connection()
    try:
        c = conn.cursor()
        scanned = c.execute("""
            SELECT i.lot,i.code_article,i.poids_physique,i.remarque,i.date_scan,u.username
            FROM inventory i LEFT JOIN users u ON i.scanned_by=u.id
        """).fetchall()
        lots_stock, _ = load_stock_data()
        result = []
        for row in scanned:
            lot = row['lot']
            tup = (
                lot,
                row['code_article'],
                row['poids_physique'],
                row['remarque'],
                row['date_scan'],
                row['username'],
                ('OK' if lot in lots_stock else 'NOK')
            )
            result.append(tup)
        return result
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_dashboard_stats():
    conn = get_db_connection()
    try:
        c = conn.cursor()
        nb = c.execute("SELECT COUNT(DISTINCT lot) as c FROM inventory").fetchone()
        nb = nb['c'] if nb else 0
        first = c.execute("SELECT MIN(date_scan) as f FROM inventory").fetchone()
        first = first['f'] if first else None
        last = c.execute("SELECT MAX(date_scan) as l FROM inventory").fetchone()
        last = last['l'] if last else None
        cadence = 0
        if first and last:
            try:
                elapsed = (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds() / 3600.0
                cadence = nb / elapsed if elapsed > 0 else 0
            except Exception:
                cadence = 0
        _, cible = load_stock_data()
        return {'nb_bobines_scannees': nb, 'cible_lot': cible, 'cadence': round(cadence, 2),
                'first_scan_time': first, 'last_scan_time': last}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_unread_messages_count():
    if not current_user or not getattr(current_user, "is_authenticated", False):
        return 0
    conn = get_db_connection()
    try:
        c = conn.cursor()
        direct = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_id=? AND is_read=0 AND is_group_message=0",
            [current_user.id]
        ).fetchone()
        direct = direct['cnt'] if direct else 0
        group = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE is_group_message=1 AND sender_id!=? AND is_read=0",
            [current_user.id]
        ).fetchone()
        group = group['cnt'] if group else 0
        return int(direct) + int(group)
    except Exception:
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass

# ==================== ROUTES ====================

# ---------- LOGIN/LOGOUT ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = get_db_connection()
        c = conn.cursor()
        try:
            res = c.execute("SELECT id,username,password_hash,role,is_active FROM users WHERE username=?",[username]).fetchone()
            if res:
                is_active = res['is_active']
                pw_hash = res['password_hash']
                role = res['role']
                uid = res['id']
                uname = res['username']
                if is_active and check_password_hash(pw_hash, password):
                    login_user(User(uid, uname, role))
                    flash('Connexion réussie','success')
                    return redirect(url_for('dashboard'))
        finally:
            try:
                conn.close()
            except Exception:
                pass
        flash('Nom d\'utilisateur ou mot de passe incorrect','error')
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
                conn = get_db_connection()
                c = conn.cursor()
                try:
                    c.execute("INSERT INTO inventory (lot,code_article,poids_physique,remarque,date_scan,scanned_by) VALUES (?,?,?,?,?,?)",
                              [lot, code_article, poids, ','.join(remarques), datetime.now().isoformat(), current_user.id])
                    conn.commit()
                    flash(f'✓ Lot {lot} ajouté','success')
                    return redirect(url_for('scan'))
                except Exception as e:
                    if 'UNIQUE constraint failed' in str(e) or 'constraint' in str(e).lower():
                        flash('Lot déjà existant ou clé primaire en conflit', 'error')
                    else:
                        flash('Erreur: ' + str(e), 'error')
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
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
            conn = get_db_connection()
            c = conn.cursor()
            try:
                c.execute("INSERT INTO inventory (lot,code_article,poids_physique,remarque,date_scan,scanned_by) VALUES (?,?,?,?,?,?)",
                          [lot, code_article, poids, ','.join(remarques), datetime.now().isoformat(), current_user.id])
                conn.commit()
                flash(f'✓ Lot {lot} ajouté','success')
                return redirect(url_for('manual_entry'))
            except Exception as e:
                if 'UNIQUE constraint failed' in str(e) or 'constraint' in str(e).lower():
                    flash('Lot déjà existant', 'error')
                else:
                    flash('Erreur: ' + str(e), 'error')
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
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

# Ajoutez cette route AVANT la route /export

@app.route('/verify-export-password', methods=['POST'])
@login_required
@admin_required
def verify_export_password():
    """Vérifie le mot de passe d'export"""
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'success': False, 'message': 'Données invalides'}), 400
    
    password = data.get('password', '')
    export_password = get_config('export_password', None)
    
    if not export_password:
        return jsonify({'success': False, 'message': 'Aucun mot de passe configuré'}), 400
    
    if check_password_hash(export_password, password):
        # Générer un token temporaire valide pour 5 minutes
        session['export_token'] = datetime.now().isoformat()
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Mot de passe incorrect'}), 401


# Modifiez la route /export existante
@app.route('/export', methods=['POST'])
@login_required
@admin_required
def export_data():
    # Vérifier le token d'export
    export_token = session.get('export_token')
    if not export_token:
        flash('Veuillez d\'abord vous authentifier pour l\'export', 'error')
        return redirect(url_for('search'))
    
    # Vérifier que le token n'a pas expiré (5 minutes)
    try:
        token_time = datetime.fromisoformat(export_token)
        if (datetime.now() - token_time).total_seconds() > 300:
            session.pop('export_token', None)
            flash('Session d\'export expirée. Veuillez vous authentifier à nouveau', 'error')
            return redirect(url_for('search'))
    except Exception:
        session.pop('export_token', None)
        flash('Token d\'export invalide', 'error')
        return redirect(url_for('search'))
    
    # Supprimer le token après utilisation
    session.pop('export_token', None)
    
    # Code d'export existant
    data = get_inventory_data()
    df = pd.DataFrame(data, columns=["Lot","Code Article","Poids Physique","Remarque","Date Scan","Scanné par","Vérification"])
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='inventory')
    output.seek(0)
    filename = f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(output, as_attachment=True, download_name=filename,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# Modifiez aussi la route /quality-export
@app.route('/quality-export')
@login_required
def quality_export():
    # Vérifier le token d'export
    export_token = session.get('export_token_quality')
    if not export_token:
        flash('Veuillez d\'abord vous authentifier pour l\'export', 'error')
        return redirect(url_for('quality_control'))
    
    # Vérifier que le token n'a pas expiré (5 minutes)
    try:
        token_time = datetime.fromisoformat(export_token)
        if (datetime.now() - token_time).total_seconds() > 300:
            session.pop('export_token_quality', None)
            flash('Session d\'export expirée. Veuillez vous authentifier à nouveau', 'error')
            return redirect(url_for('quality_control'))
    except Exception:
        session.pop('export_token_quality', None)
        flash('Token d\'export invalide', 'error')
        return redirect(url_for('quality_control'))
    
    # Supprimer le token après utilisation
    session.pop('export_token_quality', None)
    
    # Code d'export existant
    conn = get_db_connection()
    query = """
        SELECT 
            i.lot,
            i.code_article,
            i.poids_physique,
            COALESCE(qc.statut_qualite, 'EN_ATTENTE') as statut_qualite,
            qc.non_conformite,
            qc.decision_finale,
            qc.controleur_nom,
            qc.date_controle,
            i.date_scan
        FROM inventory i
        LEFT JOIN quality_control qc ON i.lot = qc.lot
        ORDER BY i.date_scan DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Contrôle Qualité', index=False)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'controle_qualite_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    )


@app.route('/verify-quality-export-password', methods=['POST'])
@login_required
def verify_quality_export_password():
    """Vérifie le mot de passe d'export qualité"""
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'success': False, 'message': 'Données invalides'}), 400
    
    password = data.get('password', '')
    export_password = get_config('export_password', None)
    
    if not export_password:
        return jsonify({'success': False, 'message': 'Aucun mot de passe configuré'}), 400
    
    if check_password_hash(export_password, password):
        session['export_token_quality'] = datetime.now().isoformat()
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Mot de passe incorrect'}), 401

# ---------- RESET ----------
@app.route('/reset', methods=['GET','POST'])
@login_required
@admin_required
def reset_inventory():
    if request.method == 'POST':
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("DELETE FROM inventory")
            conn.commit()
            flash('Inventaire réinitialisé','success')
            return redirect(url_for('dashboard'))
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return render_template('reset.html')

# ---------- USERS CRUD ----------
@app.route('/users')
@login_required
@admin_required
def users():
    conn = get_db_connection()
    c = conn.cursor()
    try:
        users_list = c.execute("SELECT id,username,full_name,role,created_at,is_active FROM users ORDER BY created_at DESC").fetchall()
        return render_template('users.html', users=users_list)
    finally:
        try:
            conn.close()
        except Exception:
            pass


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
            conn = get_db_connection()
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (username,password_hash,full_name,role,created_at,created_by) VALUES (?,?,?,?,?,?)",
                          [u, generate_password_hash(p), fn, r, datetime.now().isoformat(), current_user.id])
                conn.commit()
                flash('Utilisateur créé','success')
                return redirect(url_for('users'))
            except Exception as e:
                if 'UNIQUE constraint failed' in str(e) or 'constraint' in str(e).lower():
                    flash('Nom d\'utilisateur déjà utilisé', 'error')
                else:
                    flash('Erreur: ' + str(e), 'error')
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
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
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET is_active=1-is_active WHERE id=?", [user_id])
        conn.commit()
        flash('Statut mis à jour','success')
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return redirect(url_for('users'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('Impossible de supprimer votre compte','error')
        return redirect(url_for('users'))
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM users WHERE id=?", [user_id])
        conn.commit()
        flash('Utilisateur supprimé','success')
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return redirect(url_for('users'))

# ---------- CHAT ----------
@app.route('/chat')
@login_required
def chat():
    conn = get_db_connection()
    c = conn.cursor()
    try:
        users_list = c.execute(
            "SELECT id,username,full_name FROM users WHERE id!=? AND is_active=1 ORDER BY username",
            [current_user.id]
        ).fetchall()
        return render_template('chat.html', users=users_list)
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.route('/chat/messages')
@login_required
def chat_messages():
    chat_type = request.args.get('type', 'direct')
    other_id = request.args.get('user_id', type=int)

    conn = get_db_connection()
    try:
        c = conn.cursor()
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
            return jsonify({'error': 'type de chat inconnu'}), 400

        conn.commit()

        msgs = []
        for m in messages:
            msgs.append({
                'id': m['id'],
                'sender_id': m['sender_id'],
                'sender_username': m['username'],
                'sender_fullname': m['full_name'],
                'message': m['message'],
                'created_at': m['created_at'],
                'is_read': bool(m['is_read']),
                'is_own': (m['sender_id'] == current_user.id)
            })

        return jsonify({'messages': list(reversed(msgs))})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.route('/chat/unread_count')
@login_required
def chat_unread_count():
    conn = get_db_connection()
    c = conn.cursor()
    try:
        direct = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_id=? AND is_read=0 AND is_group_message=0",
            [current_user.id]
        ).fetchone()
        direct = direct['cnt'] if direct else 0

        group = c.execute(
            "SELECT COUNT(*) as cnt FROM chat_messages WHERE is_group_message=1 AND sender_id!=? AND is_read=0",
            [current_user.id]
        ).fetchone()
        group = group['cnt'] if group else 0

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
            unread_by_user[row['sender_id']] = {'username': row['username'], 'count': row['count']}

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
        except Exception:
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

    conn = get_db_connection()
    c = conn.cursor()
    try:
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
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            conn.close()
        except Exception:
            pass


@app.route('/chat/mark_all_read', methods=['POST'])
@login_required
def mark_all_read():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'error': 'JSON invalide'}), 400

    chat_type = data.get('type', 'direct')
    user_id = data.get('user_id')

    conn = get_db_connection()
    c = conn.cursor()
    try:
        if chat_type == 'group':
            c.execute("UPDATE chat_messages SET is_read=1 WHERE is_group_message=1 AND sender_id!=?", [current_user.id])
        elif chat_type == 'direct' and user_id:
            c.execute("UPDATE chat_messages SET is_read=1 WHERE receiver_id=? AND sender_id=? AND is_group_message=0", [current_user.id, user_id])
        else:
            return jsonify({'error': 'Paramètres invalides pour mark_all_read'}), 400

        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            conn.close()
        except Exception:
            pass

# Remplacez la route /settings existante par celle-ci

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    if request.method == 'POST':
        name = (request.form.get('company_name') or '').strip()

        if name:
            set_config('company_name', name)
            flash('Nom de l\'entreprise mis à jour', 'success')

        # Gestion du mot de passe d'export
        export_password = request.form.get('export_password', '').strip()
        if export_password:
            hashed_password = generate_password_hash(export_password)
            set_config('export_password', hashed_password)
            flash('Mot de passe d\'export configuré avec succès', 'success')

        logo_file = request.files.get('company_logo')
        if logo_file and allowed_file(logo_file.filename):
            filename = secure_filename(logo_file.filename)
            filename = 'company_' + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            logo_file.save(filepath)
            set_config('company_logo', filename)
            flash('Logo uploadé avec succès', 'success')

        return redirect(url_for('settings'))

    current_name = get_config('company_name', 'Inventory Management')
    export_password_set = get_config('export_password', None) is not None
    
    return render_template('settings.html', 
                         company_name=current_name,
                         export_password_set=export_password_set)
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
            conn = get_db_connection()
            c = conn.cursor()
            try:
                res = c.execute("SELECT password_hash FROM users WHERE id=?", [current_user.id]).fetchone()
                if res:
                    pw_hash = res['password_hash']
                    if check_password_hash(pw_hash, cp):
                        c.execute("UPDATE users SET password_hash=? WHERE id=?", [generate_password_hash(npw), current_user.id])
                        conn.commit()
                        flash('Mot de passe modifié','success')
                    else:
                        flash('Mot de passe actuel incorrect','error')
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
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
            conn = get_db_connection()
            c = conn.cursor()
            try:
                for _, row in df.iterrows():
                    try:
                        c.execute("UPDATE inventory SET poids_physique=? WHERE lot=?", [row['Poids'], row['Lot']])
                    except Exception:
                        continue
                conn.commit()
                flash('Poids mis à jour','success')
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        else:
            flash('Fichier MB52.xlsx invalide (colonnes Lot/Poids manquantes)', 'error')
    except Exception as e:
        flash('Erreur: ' + str(e), 'error')
    return redirect(url_for('search'))

# ---------- PRINT CONFIGURATION ----------
@app.route('/print/config', methods=['GET', 'POST'])
@login_required
@admin_required
def print_config():
    """Configuration des informations pour l'impression de l'inventaire"""
    if request.method == 'POST':
        set_config('print_entreprise', request.form.get('entreprise', ''))
        set_config('print_division', request.form.get('division', ''))
        set_config('print_magasin', request.form.get('magasin', ''))
        set_config('print_zone', request.form.get('zone', ''))
        set_config('print_titre', request.form.get('titre', 'Inventaire Fin 2025'))
        set_config('print_equipe_comptage', request.form.get('equipe_comptage', ''))
        set_config('print_controleur', request.form.get('controleur', ''))
        set_config('print_du', request.form.get('du', ''))
        set_config('print_controleur_gestion', request.form.get('controleur_gestion', ''))

        logo_file = request.files.get('print_logo')
        if logo_file and allowed_file(logo_file.filename):
            filename = secure_filename(logo_file.filename)
            filename = 'print_logo_' + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            logo_file.save(filepath)
            set_config('print_logo', filename)
            flash('Logo uploadé avec succès', 'success')

        flash('Configuration d\'impression enregistrée avec succès', 'success')
        return redirect(url_for('print_config'))

    config_data = {
        'entreprise': get_config('print_entreprise', ''),
        'division': get_config('print_division', ''),
        'magasin': get_config('print_magasin', ''),
        'zone': get_config('print_zone', ''),
        'titre': get_config('print_titre', 'Inventaire Fin 2025'),
        'equipe_comptage': get_config('print_equipe_comptage', ''),
        'controleur': get_config('print_controleur', ''),
        'du': get_config('print_du', ''),
        'controleur_gestion': get_config('print_controleur_gestion', '')
    }

    return render_template('print_config.html', config=config_data)


@app.route('/print/preview')
@login_required
def print_preview():
    inventory_data = get_inventory_data()
    config_data = {
        'entreprise': get_config('print_entreprise', get_config('company_name', 'Inventory Management')),
        'division': get_config('print_division', ''),
        'magasin': get_config('print_magasin', ''),
        'zone': get_config('print_zone', ''),
        'titre': get_config('print_titre', 'Inventaire Fin 2025'),
        'equipe_comptage': get_config('print_equipe_comptage', ''),
        'controleur': get_config('print_controleur', ''),
        'du': get_config('print_du', ''),
        'controleur_gestion': get_config('print_controleur_gestion', ''),
        'logo': get_config('company_logo', None)
    }
    stats = get_dashboard_stats()
    return render_template('print_preview.html', 
                         inventory_data=inventory_data, 
                         config=config_data,
                         stats=stats,
                         print_date=datetime.now().strftime('%d/%m/%Y'))

# ---------- QUALITY CONTROL ----------
@app.route('/quality-control')
@login_required
def quality_control():
    conn = get_db_connection()
    c = conn.cursor()
    
    filter_statut = request.args.get('statut', '')
    filter_decision = request.args.get('decision', '')
    search_term = request.args.get('search', '')
    
    # --- Requête principale pour les lots ---
    query = """
        SELECT 
            i.lot,
            i.code_article,
            i.poids_physique,
            i.date_scan,
            COALESCE(qc.statut_qualite, 'EN_ATTENTE') as statut_qualite,
            qc.decision_finale,
            qc.non_conformite,
            qc.controleur_nom,
            qc.date_controle
        FROM inventory i
        LEFT JOIN quality_control qc ON i.lot = qc.lot
        WHERE 1=1
    """
    params = []
    
    if filter_statut:
        query += " AND COALESCE(qc.statut_qualite, 'EN_ATTENTE') = ?"
        params.append(filter_statut)
    
    if filter_decision:
        query += " AND qc.decision_finale = ?"
        params.append(filter_decision)
    
    if search_term:
        query += " AND i.lot LIKE ?"
        params.append(f'%{search_term}%')
    
    query += " ORDER BY i.date_scan DESC"
    
    c.execute(query, params)
    lots_data = c.fetchall()
    
    lots = []
    for row in lots_data:
        lots.append({
            'lot': row['lot'],
            'code_article': row['code_article'],
            'poids_physique': row['poids_physique'],
            'date_scan': row['date_scan'],
            'statut_qualite': row['statut_qualite'],
            'decision_finale': row['decision_finale'],
            'non_conformite': row['non_conformite'],
            'controleur_nom': row['controleur_nom'],
            'date_controle': row['date_controle']
        })
    
    # --- Statistiques ---
    c.execute("""
        SELECT 
            SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'CONFORME' THEN 1 ELSE 0 END) as conformes,
            SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'NON_CONFORME' THEN 1 ELSE 0 END) as non_conformes,
            SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'EN_ATTENTE' THEN 1 ELSE 0 END) as en_attente,
            COUNT(*) as total
        FROM inventory i
        LEFT JOIN quality_control qc ON i.lot = qc.lot
    """)
    stats_row = c.fetchone()
    
    # --- Vérification None pour stats_row ---
    if stats_row is None:
        stats_row = {'conformes': 0, 'non_conformes': 0, 'en_attente': 0, 'total': 0}

    stats = {
        'conformes': stats_row.get('conformes', 0) or 0,
        'non_conformes': stats_row.get('non_conformes', 0) or 0,
        'en_attente': stats_row.get('en_attente', 0) or 0,
        'total': stats_row.get('total', 0) or 0
    }
    
    stats['taux_conformite'] = (stats['conformes'] / stats['total'] * 100) if stats['total'] > 0 else 0
    
    conn.close()
    
    return render_template('quality_control.html', 
                           lots=lots, 
                           stats=stats,
                           filter_statut=filter_statut,
                           filter_decision=filter_decision,
                           search_term=search_term)


@app.route('/save-quality-control', methods=['POST'])
@login_required
def save_quality_control():
    lot = request.form.get('lot')
    statut_qualite = request.form.get('statut_qualite')
    non_conformite = request.form.get('non_conformite', '').strip()
    decision_finale = request.form.get('decision_finale', '').strip()
    
    if not lot or not statut_qualite:
        flash('Données invalides.', 'error')
        return redirect(url_for('quality_control'))
    
    if statut_qualite == 'NON_CONFORME' and not non_conformite:
        flash('La description de la non-conformité est obligatoire.', 'error')
        return redirect(url_for('quality_control'))
    
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT code_article FROM inventory WHERE lot = ?", (lot,))
    article_row = c.fetchone()
    code_article = article_row['code_article'] if article_row else None
    
    c.execute("SELECT statut_qualite, decision_finale FROM quality_control WHERE lot = ?", (lot,))
    existing = c.fetchone()
    
    if existing:
        c.execute("""
            INSERT INTO quality_history (lot, ancien_statut, nouveau_statut, ancienne_decision, nouvelle_decision, commentaire, modifie_par)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (lot, existing['statut_qualite'], statut_qualite, existing['decision_finale'], decision_finale or None, non_conformite, current_user.username))
        
        c.execute("""
            UPDATE quality_control 
            SET statut_qualite = ?,
                non_conformite = ?,
                decision_finale = ?,
                controleur_id = ?,
                controleur_nom = ?,
                date_modification = ?
            WHERE lot = ?
        """, (statut_qualite, non_conformite or None, decision_finale or None, 
              current_user.id, current_user.username, datetime.now(), lot))
        
        flash(f'Contrôle qualité mis à jour pour le lot {lot}.', 'success')
    else:
        c.execute("""
            INSERT INTO quality_control (lot, code_article, statut_qualite, non_conformite, decision_finale, controleur_id, controleur_nom)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (lot, code_article, statut_qualite, non_conformite or None, decision_finale or None, 
              current_user.id, current_user.username))
        
        c.execute("""
            INSERT INTO quality_history (lot, ancien_statut, nouveau_statut, commentaire, modifie_par)
            VALUES (?, ?, ?, ?, ?)
        """, (lot, 'EN_ATTENTE', statut_qualite, non_conformite, current_user.username))
        
        flash(f'Contrôle qualité enregistré pour le lot {lot}.', 'success')
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('quality_control'))


@app.route('/quality-batch-update', methods=['POST'])
@login_required
def quality_batch_update():
    lots = request.form.getlist('lots')
    statut = request.form.get('statut')
    
    if not lots or not statut:
        flash('Données invalides.', 'error')
        return redirect(url_for('quality_control'))
    
    conn = get_db_connection()
    c = conn.cursor()
    
    updated = 0
    for lot in lots:
        c.execute("SELECT id FROM quality_control WHERE lot = ?", (lot,))
        exists = c.fetchone()
        
        c.execute("SELECT code_article FROM inventory WHERE lot = ?", (lot,))
        article_row = c.fetchone()
        code_article = article_row['code_article'] if article_row else None
        
        if exists:
            c.execute("""
                UPDATE quality_control 
                SET statut_qualite = ?,
                    controleur_id = ?,
                    controleur_nom = ?,
                    date_modification = ?
                WHERE lot = ?
            """, (statut, current_user.id, current_user.username, datetime.now(), lot))
        else:
            c.execute("""
                INSERT INTO quality_control (lot, code_article, statut_qualite, controleur_id, controleur_nom)
                VALUES (?, ?, ?, ?, ?)
            """, (lot, code_article, statut, current_user.id, current_user.username))
        
        c.execute("""
            INSERT INTO quality_history (lot, nouveau_statut, modifie_par)
            VALUES (?, ?, ?)
        """, (lot, statut, current_user.username))
        
        updated += 1
    
    conn.commit()
    conn.close()
    
    flash(f'{updated} lot(s) mis à jour avec le statut {statut}.', 'success')
    return redirect(url_for('quality_control'))



@app.route('/api/quality-stats')
@login_required
def quality_stats_api():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
        SELECT 
            SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'CONFORME' THEN 1 ELSE 0 END) as conformes,
            SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'NON_CONFORME' THEN 1 ELSE 0 END) as non_conformes,
            SUM(CASE WHEN COALESCE(qc.statut_qualite, 'EN_ATTENTE') = 'EN_ATTENTE' THEN 1 ELSE 0 END) as en_attente,
            COUNT(*) as total
        FROM inventory i
        LEFT JOIN quality_control qc ON i.lot = qc.lot
    """)
    
    row = c.fetchone()
    
    conformes = row['conformes'] or 0
    non_conformes = row['non_conformes'] or 0
    en_attente = row['en_attente'] or 0
    total = row['total'] or 0
    
    taux_conformite = (conformes / total * 100) if total > 0 else 0
    
    conn.close()
    
    return jsonify({
        'conformes': conformes,
        'non_conformes': non_conformes,
        'en_attente': en_attente,
        'taux_conformite': round(taux_conformite, 1)
    })

# ==================== MAIN ====================
if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=5000, debug=False)
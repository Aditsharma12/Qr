from flask import Flask, render_template, request, send_file, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from io import BytesIO
import base64
import sqlite3
import os
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['DATABASE'] = 'site.db'
app.config['ADMIN_USERNAME'] = 'adit'
app.config['ADMIN_PASSWORD_HASH'] = generate_password_hash('adit123')

# Database setup with error handling
def get_db():
    try:
        db = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        return db
    except sqlite3.Error as e:
        app.logger.error(f"Database connection error: {str(e)}")
        raise

def init_db():
    try:
        with app.app_context():
            db = get_db()
            db.execute('''
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            db.execute('''
                CREATE TABLE IF NOT EXISTS admin_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            ''')
            try:
                db.execute(
                    'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
                    (app.config['ADMIN_USERNAME'], app.config['ADMIN_PASSWORD_HASH'])
                )
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
            db.commit()
    except Exception as e:
        app.logger.error(f"Database initialization error: {str(e)}")
        raise

init_db()

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Login required decorator with error handling
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if not session.get('admin_logged_in'):
                flash('Please login to access this page', 'error')
                return redirect(url_for('admin_login'))
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"Admin required error: {str(e)}")
            flash('An error occurred during authentication', 'error')
            return redirect(url_for('admin_login'))
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about/')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip()
            message = request.form.get('message', '').strip()
            
            if not all([name, email, message]):
                return jsonify({'error': 'All fields are required'}), 400
            
            db = get_db()
            db.execute(
                'INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)',
                (name, email, message)
            )
            db.commit()
            return jsonify({'success': True, 'message': 'Thank you for your message!'})
        except Exception as e:
            app.logger.error(f"Contact form error: {str(e)}")
            return jsonify({'error': 'An error occurred while processing your message'}), 500
    
    return render_template('contact.html')

@app.route('/generate-qr', methods=['POST'])
def generate_qr():
    try:
        data = request.form.get('text', '').strip()
        if not data:
            return jsonify({'error': 'Please enter text or URL'}), 400
        
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return jsonify({'success': True, 'qr_code': qr_code, 'text': data})
    except Exception as e:
        app.logger.error(f"QR generation error: {str(e)}")
        return jsonify({'error': 'Failed to generate QR code'}), 500

@app.route('/download-qr')
def download_qr():
    try:
        text = request.args.get('text', '').strip()
        if not text:
            flash('No text provided for QR code', 'error')
            return redirect(url_for('index'))
        
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return send_file(buffer, mimetype='image/png', as_attachment=True, download_name='qrcode.png')
    except Exception as e:
        app.logger.error(f"QR download error: {str(e)}")
        flash('Failed to generate QR code for download', 'error')
        return redirect(url_for('index'))

# Admin routes with error handling
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            db = get_db()
            admin = db.execute(
                'SELECT * FROM admin_users WHERE username = ?', 
                (username,)
            ).fetchone()
            
            if admin and check_password_hash(admin['password_hash'], password):
                session['admin_logged_in'] = True
                session['admin_username'] = username
                flash('Login successful', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid credentials', 'error')
        except Exception as e:
            app.logger.error(f"Admin login error: {str(e)}")
            flash('An error occurred during login', 'error')
    
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        if not session.get('admin_logged_in'):
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('admin_login'))

        db = get_db()
        
        # Get recent contacts (last 7 days)
        recent_contacts = db.execute('''
            SELECT * FROM contacts 
            WHERE created_at >= datetime('now', '-7 days')
            ORDER BY created_at DESC
        ''').fetchall()
        
        # Get total contacts count
        total_result = db.execute('SELECT COUNT(*) as count FROM contacts').fetchone()
        total_contacts = total_result['count'] if total_result else 0
        
        # Get recent contacts count
        recent_count = len(recent_contacts) if recent_contacts else 0
        
        # Get last 10 contacts
        contacts = db.execute('''
            SELECT * FROM contacts 
            ORDER BY created_at DESC 
            LIMIT 10
        ''').fetchall()
        
        return render_template('admin/dashboard.html',
                            contacts=contacts,
                            contacts_count=total_contacts,
                            recent_contacts_count=recent_count)
        
    except sqlite3.Error as db_error:
        app.logger.error(f"Database error in dashboard: {str(db_error)}")
        flash('Database error occurred while loading dashboard', 'error')
        return redirect(url_for('admin_login'))
    except Exception as e:
        app.logger.error(f"Unexpected error in dashboard: {str(e)}")
        flash('Failed to load dashboard data', 'error')
        return redirect(url_for('admin_login'))
    
@app.route('/admin/logout')
def admin_logout():
    try:
        session.pop('admin_logged_in', None)
        session.pop('admin_username', None)
        flash('You have been logged out', 'success')
    except Exception as e:
        app.logger.error(f"Logout error: {str(e)}")
        flash('An error occurred during logout', 'error')
    return redirect(url_for('admin_login'))

# Legacy route handling
@app.route('/login')
@app.route('/logout')
def legacy_admin_routes():
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.run(debug=True)
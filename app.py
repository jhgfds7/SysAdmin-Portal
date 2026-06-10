import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import re

# Load Environment Variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-dev-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='regular')
    is_active = db.Column(db.Boolean, default=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='logs')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(user_id, action):
    log = AuditLog(user_id=user_id, action=action)
    db.session.add(log)
    db.session.commit()

# --- HELPERS ---
def validate_password(password):
    """Ensure password meets complexity requirements"""
    if len(password) < 8 or not re.search("[a-z]", password) or not re.search("[A-Z]", password) or not re.search("[0-9]", password):
        return False
    return True

# --- PUBLIC ROUTES ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Rate limiting against brute force
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            if not user.is_active:
                flash("Your account has been disabled by an administrator.", "error")
                return redirect(url_for('login'))
            login_user(user)
            log_action(user.id, "Logged in")
            return redirect(url_for('dashboard'))
        flash("Invalid username or password", "error")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username, email, password = request.form['username'], request.form['email'], request.form['password']
        
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash("Username or Email already exists.", "error")
        elif not validate_password(password):
            flash("Password must be at least 8 characters long and contain uppercase, lowercase, and numbers.", "error")
        else:
            new_user = User(username=username, email=email, password_hash=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            log_action(new_user.id, "Registered account")
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    log_action(current_user.id, "Logged out")
    logout_user()
    return redirect(url_for('login'))

# --- REGULAR USER ROUTES ---
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('profile.html', user=current_user)

@app.route('/profile/edit', methods=['POST'])
@login_required
def edit_profile():
    current_user.email = request.form['email']
    
    new_password = request.form.get('new_password')
    if new_password:
        if validate_password(new_password):
            current_user.password_hash = generate_password_hash(new_password)
            log_action(current_user.id, "Changed own password")
        else:
            flash("New password does not meet complexity requirements.", "error")
            return redirect(url_for('dashboard'))
            
    db.session.commit()
    log_action(current_user.id, "Updated profile information")
    flash("Profile updated successfully.", "success")
    return redirect(url_for('dashboard'))

# --- ADMIN ROUTES ---
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin': abort(403)
    
    # Search and Filter Logic
    query_str = request.args.get('q', '')
    role_filter = request.args.get('role', '')
    
    users_query = User.query
    if query_str:
        users_query = users_query.filter((User.username.contains(query_str)) | (User.email.contains(query_str)))
    if role_filter:
        users_query = users_query.filter_by(role=role_filter)
        
    users = users_query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('admin_dashboard.html', users=users, logs=logs)
@app.route('/admin/user/add', methods=['POST'])
@login_required
def admin_add_user():
    if current_user.role != 'admin': abort(403)
    
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        flash("Username or Email already exists.", "error")
    elif not validate_password(password):
        flash("Password does not meet complexity requirements.", "error")
    else:
        new_user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role)
        db.session.add(new_user)
        db.session.commit()
        log_action(current_user.id, f"Admin created new user: {username}")
        flash(f"User {username} successfully added.", "success")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_user(id):
    if current_user.role != 'admin': abort(403)
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        log_action(current_user.id, f"Modified information for user: {user.username}")
        flash(f"User {user.username} updated successfully.", "success")
        return redirect(url_for('admin_dashboard'))
        
    return render_template('admin_edit_user.html', user=user)
@app.route('/admin/user/<int:id>/toggle')
@login_required
def toggle_user(id):
    if current_user.role != 'admin': abort(403)
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash("You cannot disable yourself.", "error")
        return redirect(url_for('admin_dashboard'))
        
    user.is_active = not user.is_active
    db.session.commit()
    status = "Enabled" if user.is_active else "Disabled"
    log_action(current_user.id, f"{status} user: {user.username}")
    flash(f"User {user.username} has been {status}.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:id>/reset_password')
@login_required
def reset_user_password(id):
    if current_user.role != 'admin': abort(403)
    user = User.query.get_or_404(id)
    user.password_hash = generate_password_hash("DefaultPass123!")
    db.session.commit()
    log_action(current_user.id, f"Reset password for user: {user.username}")
    flash(f"Password for {user.username} reset to 'DefaultPass123!'", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:id>/delete')
@login_required
def delete_user(id):
    if current_user.role != 'admin': abort(403)
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash("You cannot delete yourself.", "error")
        return redirect(url_for('admin_dashboard'))
        
    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_action(current_user.id, f"Deleted user: {username}")
    flash(f"User {username} deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))

# --- INITIALIZATION ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Auto-create admin if none exists
        if not User.query.filter_by(role='admin').first():
            admin = User(username='admin', email='admin@system.local', 
                         password_hash=generate_password_hash('Admin@1234'), role='admin')
            db.session.add(admin)
            db.session.commit()
            print("Default Admin Created - User: admin | Pass: Admin@1234")
            
    app.run(debug=True)
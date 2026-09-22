from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from auth.models import db, User
from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        pin = request.form.get('pin', '')
        confirm_pin = request.form.get('confirm_pin', '')
        
        if not username or not password or not pin:
            flash('Username, password, and PIN are required', 'error')
            return render_template('register.html')
            
        if not pin.isdigit() or len(pin) != 6:
            flash('PIN must be exactly 6 numeric digits', 'error')
            return render_template('register.html')
            
        if pin != confirm_pin:
            flash('PINs do not match', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        # Use standard application-level password hashing
        password_hash = generate_password_hash(password)
        pin_hash = generate_password_hash(pin)
        
        user = User(username=username, password_hash=password_hash, pin_hash=pin_hash)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        
        # Verify using standard application-level password hashing
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully', 'success')
            return redirect(url_for('documents.dashboard'))
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, flash
from app.models import db, Transactions, User  # Import model User
from werkzeug.security import generate_password_hash # Tambahkan import yang hilang
from app.crypto_utils import generate_or_load_keys, encrypt_data, decrypt_data, hash_data
from functools import wraps
from sqlalchemy import text
from datetime import datetime

routes = Blueprint('routes', __name__)

# Load RSA Keys saat aplikasi dimulai
private_key, public_key = generate_or_load_keys()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('routes.login'))
        return f(*args, **kwargs)
    return decorated_function

@routes.route('/')
def home():
    return render_template('index.html')

@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validasi input
        if not username or not email or not password:
            flash('All fields are required!', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')
        
        # Cek apakah username atau email sudah ada
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('Username or email already exists!', 'danger')
            return render_template('register.html')
        
        # Buat user baru
        try:
            new_user = User(username=username, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('routes.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {e}', 'danger')
    
    return render_template('register.html')

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return render_template('login.html')
        
        # Cari user di database
        user = User.query.filter_by(username=username).first()
        
        # Verifikasi password
        if user and user.verify_password(password):
            # Set session variables
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful! Welcome to PayShield.', 'success')
            return redirect(url_for('routes.dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    
    return render_template('login.html')

@routes.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('routes.home'))

@routes.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get user_id from session
        user_id = session.get('user_id')
        
        # Get the latest 5 transactions for dashboard
        result = db.session.execute(text("""
            SELECT id, encrypted_name, encrypted_amount, created_at 
            FROM transactions 
            WHERE user_id = :user_id
            ORDER BY id DESC LIMIT 5
        """), {'user_id': user_id})
        
        transactions = []
        for row in result.fetchall():
            try:
                transactions.append({
                    'id': row[0],
                    'name': decrypt_data(private_key, row[1]),
                    'amount': decrypt_data(private_key, row[2]),
                    'created_at': row[3].strftime('%Y-%m-%d %H:%M') if row[3] else 'N/A'
                })
            except Exception as e:
                # Jangan tampilkan flash error untuk setiap dekripsi yang gagal
                # Tambahkan transaksi dengan label [Tidak Tersedia]
                transactions.append({
                    'id': row[0],
                    'name': "[Tidak Tersedia]",
                    'amount': "[Tidak Tersedia]",
                    'created_at': row[3].strftime('%Y-%m-%d %H:%M') if row[3] else 'N/A'
                })
                continue
    except Exception as e:
        flash(f'Error retrieving transactions: {str(e)}', 'danger')
        transactions = []
        
    return render_template('dashboard.html', username=session.get('username'), transactions=transactions)

@routes.route('/transactions', methods=['GET', 'POST'])
@login_required
def transactions():
    user_id = session.get('user_id')
    
    if request.method == 'POST':
        transaction_name = request.form['transaction_name']
        amount = request.form['amount']

        if not transaction_name or not amount:
            flash('All fields are required!', 'danger')
            return redirect(url_for('routes.transactions'))

        try:
            encrypted_name = encrypt_data(public_key, transaction_name)
            encrypted_amount = encrypt_data(public_key, amount)
            hashed_name = hash_data(transaction_name)
            hashed_amount = hash_data(amount)
            hash_value = hash_data(f"{transaction_name}:{amount}")
            
            # Tambahkan transaksi baru dengan ORM
            new_transaction = Transactions(
                encrypted_name=encrypted_name,
                encrypted_amount=encrypted_amount,
                hash_name=hashed_name,
                hash_amount=hashed_amount,
                user_id=user_id,
                encrypted_data="",
                hash_value=hash_value 
            )
            
            db.session.add(new_transaction)
            db.session.commit()
            
            flash('Transaction added successfully!', 'success')
        except Exception as e:
            flash(f'Error adding transaction: {str(e)}', 'danger')
            db.session.rollback()

        return redirect(url_for('routes.transactions'))

    # Fetch all transactions for current user and decrypt
    try:
        result = db.session.execute(text("""
            SELECT id, encrypted_name, encrypted_amount, created_at 
            FROM transactions 
            WHERE user_id = :user_id
            ORDER BY id DESC
        """), {'user_id': user_id})
        
        transactions = []
        for row in result.fetchall():
            try:
                decrypted_name = decrypt_data(private_key, row[1])
                decrypted_amount = decrypt_data(private_key, row[2])
                
                transactions.append({
                    'id': row[0],
                    'name': decrypted_name,
                    'amount': decrypted_amount,
                    'encrypted_name': row[1],
                    'encrypted_amount': row[2],
                    'created_at': row[3].strftime('%Y-%m-%d %H:%M') if row[3] else 'N/A'
                })
            except Exception as e:
                # Tambahkan data yang gagal didekripsi dengan note
                transactions.append({
                    'id': row[0],
                    'name': "[Decryption failed]",
                    'amount': "[Decryption failed]",
                    'encrypted_name': row[1],
                    'encrypted_amount': row[2],
                    'created_at': row[3].strftime('%Y-%m-%d %H:%M') if row[3] else 'N/A'
                })
                continue
    except Exception as e:
        flash(f'Error retrieving transactions: {str(e)}', 'danger')
        transactions = []

    return render_template('transactions.html', transactions=transactions)

@routes.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        email = request.form['email']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if email and email != user.email:
            # Verifikasi bahwa email belum digunakan
            existing_email = User.query.filter_by(email=email).first()
            if existing_email and existing_email.id != user_id:
                flash('Email already in use by another account', 'danger')
            else:
                user.email = email
                flash('Email updated successfully', 'success')
        
        if current_password and new_password and confirm_password:
            if not user.verify_password(current_password):
                flash('Current password is incorrect', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match', 'danger')
            else:
                user.password_hash = generate_password_hash(new_password)
                flash('Password updated successfully', 'success')
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
    
    return render_template('profile.html', user=user)
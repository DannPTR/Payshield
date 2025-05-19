from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Transactions(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    encrypted_name = db.Column(db.Text, nullable=False)
    encrypted_amount = db.Column(db.Text, nullable=False)
    encrypted_data = db.Column(db.Text, nullable=False)  # Sudah ditambahkan sebelumnya
    hash_name = db.Column(db.String(64), nullable=False)
    hash_amount = db.Column(db.String(64), nullable=False)
    hash_value = db.Column(db.String(64), nullable=False)  # Tambahkan ini
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relasi ke User
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))
    
    def __init__(self, encrypted_name, encrypted_amount, hash_name, hash_amount, 
                user_id, encrypted_data="", hash_value=""):
        self.encrypted_name = encrypted_name
        self.encrypted_amount = encrypted_amount
        self.hash_name = hash_name
        self.hash_amount = hash_amount
        self.user_id = user_id
        self.encrypted_data = encrypted_data
        self.hash_value = hash_value  # Tambahkan ini
    
    def __repr__(self):
        return f'<Transaction {self.id}>'

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'
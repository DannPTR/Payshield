import os

class Config:
    # Flask core settings
    SECRET_KEY = os.urandom(24)  # Atur kunci secara aman
    
    # Session settings
    SESSION_TYPE = 'filesystem'
    
    # Database settings for SQLAlchemy
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:@localhost/payshield'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # MySQL settings for Flask-MySQLdb
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = ''
    MYSQL_DB = 'payshield'
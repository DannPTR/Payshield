from flask import Flask
from flask_session import Session
from app.models import db
from flask_mysqldb import MySQL

mysql = MySQL()

def create_default_user(app):
    with app.app_context():
        # Use inspector to check if table exists
        from sqlalchemy import inspect
        from app.models import db, User
        
        inspector = inspect(db.engine)
        if 'users' in inspector.get_table_names():
            # Check if admin user exists
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                # Create default admin user
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    password='password'  # Password will be hashed in __init__
                )
                db.session.add(admin)
                db.session.commit()
                print('Default admin user created')
                
def create_app():
    # Create Flask app with template folder specified
    app = Flask(__name__, template_folder='../templates')
    
    # Load configurations from config file
    app.config.from_object('config.Config')
    
    # Configure MySQL
    mysql.init_app(app)
    
    # Set basic configurations
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SESSION_TYPE'] = 'filesystem'
    
    # Configure database (MySQL with SQLAlchemy)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/payshield'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions
    Session(app)
    db.init_app(app)
    
    # Only import routes after app is created to avoid circular imports
    from app.routes import routes
    
    # Register blueprint
    app.register_blueprint(routes)
    
    # Create tables if they don't exist (optional)
    with app.app_context():
        db.create_all()
        create_default_user(app)
    
    return app

from app import app, db
from models import User
from datetime import date
from werkzeug.security import generate_password_hash

def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        # Create admin user
        admin = User(
            username='admin',
            password=generate_password_hash('admin'),
            fullname='Admin',
            qualification='Administrator',
            dob=date(2000, 1, 1),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    init_db()
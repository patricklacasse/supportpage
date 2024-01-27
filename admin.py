from flask_bcrypt import Bcrypt
from app import app, db, User, Staff

bcrypt = Bcrypt(app)

def add_admin():
    admin_username = 'admin'
    admin_password = 'Momdad3639#$'  # You should use a secure password and consider hashing it with bcrypt
    admin_email = 'admin@example.com'

    # Check if the admin user already exists
    existing_admin = User.query.filter_by(username=admin_username).first()

    if existing_admin:
        print("Admin user already exists.")
    else:
        # Create and add the admin user to the database
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin_user = User(username=admin_username, password=hashed_password, email=admin_email)
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user added successfully.")

if __name__ == '__main__':
    with app.app_context():
        # Initialize Flask app and database
        db.create_all()
        
        # Add the admin user to the database
        add_admin()

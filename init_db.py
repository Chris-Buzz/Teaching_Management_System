"""
Initialize database tables only - NO sample data
Run this script to create empty database tables for production
"""
from app import app, db

def init_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database tables created successfully!")
        print("\nThe database is ready for use.")
        print("No sample data has been added.")
        print("\nYou can now run the application with: python app.py")
        print("Register your first user through the web interface.")

if __name__ == "__main__":
    init_database()
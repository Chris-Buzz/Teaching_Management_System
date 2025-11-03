"""
Reset database - drops all tables and recreates them
WARNING: This will delete all data!
"""
from app import app, db

def reset_database():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        print("Dropped all existing tables")

        # Create all tables with new schema
        db.create_all()
        print("Created all tables with updated schema")
        print("\nDatabase has been reset successfully!")
        print("You can now run the application with: python app.py")

if __name__ == "__main__":
    confirm = input("This will DELETE ALL DATA. Type 'yes' to continue: ")
    if confirm.lower() == 'yes':
        reset_database()
    else:
        print("Operation cancelled")

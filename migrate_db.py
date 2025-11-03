"""
Database migration script to add password reset fields
Run this script to update the existing database with new columns
"""
from app import app, db
import sqlite3

def migrate_database():
    with app.app_context():
        # Get database path
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')

        # Connect to SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        try:
            # Check if columns already exist
            cursor.execute("PRAGMA table_info(user)")
            columns = [column[1] for column in cursor.fetchall()]

            # Add reset_token column if it doesn't exist
            if 'reset_token' not in columns:
                cursor.execute("ALTER TABLE user ADD COLUMN reset_token VARCHAR(100)")
                print("Added reset_token column")
            else:
                print("reset_token column already exists")

            # Add reset_token_expiry column if it doesn't exist
            if 'reset_token_expiry' not in columns:
                cursor.execute("ALTER TABLE user ADD COLUMN reset_token_expiry DATETIME")
                print("Added reset_token_expiry column")
            else:
                print("reset_token_expiry column already exists")

            conn.commit()
            print("\nDatabase migration completed successfully!")

        except Exception as e:
            print(f"Error during migration: {e}")
            conn.rollback()
        finally:
            conn.close()

if __name__ == "__main__":
    migrate_database()

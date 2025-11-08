"""
Database migration script to add support for pending students
This adds new columns to existing tables to support students who haven't registered yet
"""
from app import app, db
from sqlalchemy import text

def migrate_database():
    with app.app_context():
        print("Starting database migration...")
        
        try:
            # Create new PendingStudent table
            print("Creating PendingStudent table...")
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS pending_student (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(100) NOT NULL,
                    name VARCHAR(100),
                    added_by_teacher_id INTEGER NOT NULL REFERENCES "user"(id),
                    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            
            # Add new columns to Enrollment table
            print("Adding columns to Enrollment table...")
            db.session.execute(text("""
                ALTER TABLE enrollment 
                ADD COLUMN IF NOT EXISTS student_email VARCHAR(100),
                ADD COLUMN IF NOT EXISTS student_name VARCHAR(100),
                ADD COLUMN IF NOT EXISTS enrollment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            """))
            
            # Make student_id nullable in Enrollment
            print("Making student_id nullable in Enrollment table...")
            db.session.execute(text("""
                ALTER TABLE enrollment 
                ALTER COLUMN student_id DROP NOT NULL
            """))
            
            # Add new columns to AttendanceRecord table
            print("Adding student_email column to AttendanceRecord table...")
            db.session.execute(text("""
                ALTER TABLE attendance_record 
                ADD COLUMN IF NOT EXISTS student_email VARCHAR(100)
            """))
            
            # Make student_id nullable in AttendanceRecord
            print("Making student_id nullable in AttendanceRecord table...")
            db.session.execute(text("""
                ALTER TABLE attendance_record 
                ALTER COLUMN student_id DROP NOT NULL
            """))
            
            db.session.commit()
            print("\n✅ Database migration completed successfully!")
            print("\nNew features:")
            print("- Teachers can now add students by email even if they haven't registered")
            print("- Students can check in with their email address")
            print("- When students register, they're automatically connected to their classes")
            
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ Migration failed: {str(e)}")
            print("\nIf you're using SQLite, you may need to recreate the database.")
            print("For PostgreSQL (Supabase), the migration should work automatically.")
            raise

if __name__ == "__main__":
    migrate_database()

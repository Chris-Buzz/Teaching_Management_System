"""
Initialize Supabase database tables
Run this script once to create all necessary tables in your Supabase PostgreSQL database
"""
from app import app, db
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def init_supabase_database():
    with app.app_context():
        try:
            # Drop all existing tables (be careful in production!)
            print("Dropping existing tables if any...")
            db.drop_all()

            # Create all tables
            print("Creating database tables...")
            db.create_all()

            print("\n" + "="*50)
            print("Supabase database tables created successfully!")
            print("="*50)
            print("\nTables created:")
            print("  - user (for teachers and students)")
            print("  - class (for courses)")
            print("  - enrollment (student-class relationships)")
            print("  - attendance_session (QR code sessions)")
            print("  - attendance_record (attendance tracking)")
            print("\nThe database is ready for use.")
            print("No sample data has been added.")
            print("\nNext steps:")
            print("1. Go to your Vercel deployment URL")
            print("2. Register your first teacher account")
            print("3. Register student accounts")
            print("4. Teachers can then create classes and add students")

        except Exception as e:
            print(f"\nError creating database tables: {e}")
            print("\nPlease check:")
            print("1. Your DATABASE_URL in .env file is correct")
            print("2. Your Supabase database password is correct")
            print("3. Your internet connection is working")

if __name__ == "__main__":
    print("Supabase Database Initialization")
    print("="*50)
    confirm = input("\nThis will reset your database. Continue? (yes/no): ")
    if confirm.lower() == 'yes':
        init_supabase_database()
    else:
        print("Operation cancelled")

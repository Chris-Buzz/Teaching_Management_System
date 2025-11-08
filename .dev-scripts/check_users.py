"""
Check what users exist in the database
"""
from app import app, db, User, Class, Enrollment, AttendanceSession
from dotenv import load_dotenv

load_dotenv()

def check_database():
    with app.app_context():
        try:
            print("="*60)
            print("DATABASE CONTENTS CHECK")
            print("="*60)

            # Check all users
            all_users = User.query.all()
            print(f"\nTotal Users: {len(all_users)}")
            print("-"*60)

            teachers = User.query.filter_by(role='teacher').all()
            students = User.query.filter_by(role='student').all()

            print(f"\nTeachers ({len(teachers)}):")
            for teacher in teachers:
                print(f"  - {teacher.name} ({teacher.email})")

            print(f"\nStudents ({len(students)}):")
            for student in students:
                print(f"  - {student.name} ({student.email}) [ID: {student.id}]")

            # Check all classes
            all_classes = Class.query.all()
            print(f"\n\nTotal Classes: {len(all_classes)}")
            print("-"*60)
            for cls in all_classes:
                print(f"  - {cls.name} ({cls.code})")
                enrollments = Enrollment.query.filter_by(class_id=cls.id).all()
                print(f"    Enrolled students: {len(enrollments)}")
                for enrollment in enrollments:
                    student = User.query.get(enrollment.student_id)
                    if student:
                        print(f"      * {student.name} ({student.email})")

            # Check active sessions
            active_sessions = AttendanceSession.query.filter_by(is_active=True).all()
            print(f"\n\nActive Attendance Sessions: {len(active_sessions)}")
            print("-"*60)
            for session in active_sessions:
                cls = Class.query.get(session.class_id)
                print(f"  - {cls.name} - Token: {session.qr_token[:20]}...")
                print(f"    Date: {session.date}")
                print(f"    Check-in URL: /check_in?token={session.qr_token}")

            print("\n" + "="*60)

        except Exception as e:
            print(f"\nError: {e}")
            print("\nMake sure:")
            print("1. Your .env file has the correct DATABASE_URL")
            print("2. You've run init_supabase_db.py to create tables")
            print("3. Your Supabase password is correct")

if __name__ == "__main__":
    check_database()

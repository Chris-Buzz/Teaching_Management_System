from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets
import qrcode
import io
import csv
from functools import wraps
import os

app = Flask(__name__)

# Configuration for production and development
if os.environ.get('VERCEL_ENV') == 'production':
    # Production configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    # Use PostgreSQL or another production database
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:////tmp/attendance.db')
else:
    # Development configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///attendance.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'teacher' or 'student'
    student_id = db.Column(db.String(50))  # Only for students
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    teacher = db.relationship('User', backref='classes_taught')

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_ref = db.relationship('Class', backref='enrollments')
    student = db.relationship('User', backref='enrollments')

class AttendanceSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    qr_token = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    class_ref = db.relationship('Class', backref='sessions')

class AttendanceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('attendance_session.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'Present', 'Late', or 'Absent'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    session = db.relationship('AttendanceSession', backref='records')
    student = db.relationship('User', backref='attendance_records')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorator for teacher-only routes
def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'teacher':
            flash('Access denied. Teachers only.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        student_id = request.form.get('student_id')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        user = User(name=name, email=email, role=role, student_id=student_id)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/teacher/dashboard')
@login_required
@teacher_required
def teacher_dashboard():
    classes = Class.query.filter_by(teacher_id=current_user.id).all()
    return render_template('teacher_dashboard.html', classes=classes)

@app.route('/teacher/class/add', methods=['GET', 'POST'])
@login_required
@teacher_required
def add_class():
    if request.method == 'POST':
        name = request.form.get('name')
        code = request.form.get('code')
        description = request.form.get('description')
        
        new_class = Class(name=name, code=code, description=description, teacher_id=current_user.id)
        db.session.add(new_class)
        db.session.commit()
        
        flash(f'Class "{name}" added successfully!', 'success')
        return redirect(url_for('teacher_dashboard'))
    
    return render_template('add_class.html')

@app.route('/teacher/class/<int:class_id>')
@login_required
@teacher_required
def view_class(class_id):
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    enrollments = Enrollment.query.filter_by(class_id=class_id).all()
    students = [e.student for e in enrollments]
    sessions = AttendanceSession.query.filter_by(class_id=class_id).order_by(AttendanceSession.date.desc()).all()
    
    return render_template('view_class.html', class_obj=class_obj, students=students, sessions=sessions)

@app.route('/teacher/class/<int:class_id>/edit', methods=['GET', 'POST'])
@login_required
@teacher_required
def edit_class(class_id):
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    if request.method == 'POST':
        class_obj.name = request.form.get('name')
        class_obj.code = request.form.get('code')
        class_obj.description = request.form.get('description')
        db.session.commit()
        
        flash('Class updated successfully!', 'success')
        return redirect(url_for('view_class', class_id=class_id))
    
    return render_template('edit_class.html', class_obj=class_obj)

@app.route('/teacher/class/<int:class_id>/delete', methods=['POST'])
@login_required
@teacher_required
def delete_class(class_id):
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    # Delete all related records
    Enrollment.query.filter_by(class_id=class_id).delete()
    sessions = AttendanceSession.query.filter_by(class_id=class_id).all()
    for session in sessions:
        AttendanceRecord.query.filter_by(session_id=session.id).delete()
    AttendanceSession.query.filter_by(class_id=class_id).delete()
    
    db.session.delete(class_obj)
    db.session.commit()
    
    flash('Class deleted successfully!', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/class/<int:class_id>/add_student', methods=['GET', 'POST'])
@login_required
@teacher_required
def add_student(class_id):
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        student = User.query.filter_by(email=email, role='student').first()
        
        if not student:
            flash('Student not found. They may need to register first.', 'warning')
            return redirect(url_for('add_student', class_id=class_id))
        
        # Check if already enrolled
        existing = Enrollment.query.filter_by(class_id=class_id, student_id=student.id).first()
        if existing:
            flash('Student is already enrolled in this class.', 'warning')
            return redirect(url_for('view_class', class_id=class_id))
        
        enrollment = Enrollment(class_id=class_id, student_id=student.id)
        db.session.add(enrollment)
        db.session.commit()
        
        flash(f'{student.name} added to class!', 'success')
        return redirect(url_for('view_class', class_id=class_id))
    
    return render_template('add_student.html', class_obj=class_obj)

@app.route('/teacher/class/<int:class_id>/remove_student/<int:student_id>', methods=['POST'])
@login_required
@teacher_required
def remove_student(class_id, student_id):
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    enrollment = Enrollment.query.filter_by(class_id=class_id, student_id=student_id).first()
    if enrollment:
        db.session.delete(enrollment)
        db.session.commit()
        flash('Student removed from class.', 'success')
    
    return redirect(url_for('view_class', class_id=class_id))

@app.route('/teacher/session/<int:class_id>/start', methods=['POST'])
@login_required
@teacher_required
def start_session(class_id):
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    # Check if there's already an active session
    active_session = AttendanceSession.query.filter_by(class_id=class_id, is_active=True).first()
    if active_session:
        flash('There is already an active session for this class.', 'warning')
        return redirect(url_for('view_session', session_id=active_session.id))
    
    # Create new session
    token = secrets.token_urlsafe(16)
    session_obj = AttendanceSession(class_id=class_id, qr_token=token)
    db.session.add(session_obj)
    db.session.commit()
    
    flash('Attendance session started!', 'success')
    return redirect(url_for('view_session', session_id=session_obj.id))

@app.route('/teacher/session/<int:session_id>')
@login_required
@teacher_required
def view_session(session_id):
    session_obj = AttendanceSession.query.get_or_404(session_id)
    class_obj = session_obj.class_ref
    
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    records = AttendanceRecord.query.filter_by(session_id=session_id).all()
    present_students = {r.student_id for r in records if r.status == 'Present'}
    
    enrollments = Enrollment.query.filter_by(class_id=class_obj.id).all()
    all_students = [e.student for e in enrollments]
    
    return render_template('view_session.html', session=session_obj, class_obj=class_obj, 
                         records=records, all_students=all_students, present_students=present_students)

@app.route('/teacher/session/<int:session_id>/close', methods=['POST'])
@login_required
@teacher_required
def close_session(session_id):
    session_obj = AttendanceSession.query.get_or_404(session_id)
    class_obj = session_obj.class_ref
    
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    # Mark session as inactive
    session_obj.is_active = False
    
    # Get all enrolled students
    enrollments = Enrollment.query.filter_by(class_id=class_obj.id).all()
    
    # Mark absent students
    for enrollment in enrollments:
        existing_record = AttendanceRecord.query.filter_by(
            session_id=session_id, student_id=enrollment.student_id
        ).first()
        
        if not existing_record:
            absent_record = AttendanceRecord(
                session_id=session_id,
                student_id=enrollment.student_id,
                status='Absent'
            )
            db.session.add(absent_record)
    
    db.session.commit()
    flash('Session closed. All remaining students marked absent.', 'success')
    return redirect(url_for('view_class', class_id=class_obj.id))

@app.route('/session/qr/<int:session_id>')
@login_required
@teacher_required
def generate_qr(session_id):
    session_obj = AttendanceSession.query.get_or_404(session_id)

    # Generate QR code
    url = request.url_root + 'check_in?token=' + session_obj.qr_token

    # Use qrcode with PIL/Pillow for Vercel compatibility
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    # Create image with explicit PIL backend
    img = qr.make_image(fill_color="black", back_color="white")

    # Save to BytesIO with explicit format
    img_io = io.BytesIO()
    img.save(img_io, format='PNG')
    img_io.seek(0)

    # Return with proper headers for Vercel
    return send_file(
        img_io,
        mimetype='image/png',
        as_attachment=False,
        download_name=f'qr_session_{session_id}.png'
    )

@app.route('/check_in', methods=['GET', 'POST'])
def check_in():
    token = request.args.get('token')

    if not token:
        flash('Invalid check-in link', 'danger')
        return redirect(url_for('index'))

    # Find the session
    session_obj = AttendanceSession.query.filter_by(qr_token=token).first()

    if not session_obj:
        flash('Invalid or expired attendance session', 'danger')
        return redirect(url_for('index'))

    if not session_obj.is_active:
        flash('This attendance session has been closed', 'warning')
        return redirect(url_for('index'))

    # If user is logged in
    if current_user.is_authenticated:
        # Check if student is enrolled
        if current_user.role != 'student':
            flash('Only students can check in', 'danger')
            return redirect(url_for('index'))

        enrollment = Enrollment.query.filter_by(
            class_id=session_obj.class_id,
            student_id=current_user.id
        ).first()

        if not enrollment:
            flash('You are not enrolled in this class', 'danger')
            return redirect(url_for('student_dashboard'))

        # Check if already checked in
        existing_record = AttendanceRecord.query.filter_by(
            session_id=session_obj.id,
            student_id=current_user.id
        ).first()

        if existing_record:
            flash('You have already checked in for this session', 'info')
            return redirect(url_for('student_dashboard'))

        # Create attendance record
        record = AttendanceRecord(
            session_id=session_obj.id,
            student_id=current_user.id,
            status='Present'
        )
        db.session.add(record)
        db.session.commit()

        flash(f'✓ Attendance marked for {session_obj.class_ref.name}!', 'success')
        return redirect(url_for('student_dashboard'))

    # If user is not logged in, show a form to enter their email
    if request.method == 'POST':
        email = request.form.get('email')
        student = User.query.filter_by(email=email, role='student').first()

        if not student:
            flash('Student not found. Please check your email or register first.', 'danger')
            return render_template('check_in.html', session=session_obj, token=token)

        # Check if student is enrolled
        enrollment = Enrollment.query.filter_by(
            class_id=session_obj.class_id,
            student_id=student.id
        ).first()

        if not enrollment:
            flash('You are not enrolled in this class', 'danger')
            return render_template('check_in.html', session=session_obj, token=token)

        # Check if already checked in
        existing_record = AttendanceRecord.query.filter_by(
            session_id=session_obj.id,
            student_id=student.id
        ).first()

        if existing_record:
            flash('You have already checked in for this session', 'info')
            return render_template('check_in.html', session=session_obj, token=token)

        # Create attendance record
        record = AttendanceRecord(
            session_id=session_obj.id,
            student_id=student.id,
            status='Present'
        )
        db.session.add(record)
        db.session.commit()

        flash(f'✓ Attendance marked for {session_obj.class_ref.name}!', 'success')
        return render_template('check_in.html', session=session_obj, token=token, success=True)

    return render_template('check_in.html', session=session_obj, token=token)

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('teacher_dashboard'))
    
    # Get enrolled classes
    enrollments = Enrollment.query.filter_by(student_id=current_user.id).all()
    
    # Get attendance data for each class
    attendance_data = []
    for enrollment in enrollments:
        class_obj = enrollment.class_ref
        sessions = AttendanceSession.query.filter_by(class_id=class_obj.id, is_active=False).all()
        
        total_sessions = len(sessions)
        present_count = 0
        
        for session in sessions:
            record = AttendanceRecord.query.filter_by(
                session_id=session.id,
                student_id=current_user.id,
                status='Present'
            ).first()
            if record:
                present_count += 1
        
        percentage = (present_count / total_sessions * 100) if total_sessions > 0 else 0
        
        attendance_data.append({
            'class': class_obj,
            'total': total_sessions,
            'present': present_count,
            'absent': total_sessions - present_count,
            'percentage': round(percentage, 1)
        })
    
    return render_template('student_dashboard.html', attendance_data=attendance_data)

@app.route('/student/class/<int:class_id>/history')
@login_required
def student_class_history(class_id):
    if current_user.role != 'student':
        return redirect(url_for('teacher_dashboard'))
    
    # Check enrollment
    enrollment = Enrollment.query.filter_by(class_id=class_id, student_id=current_user.id).first()
    if not enrollment:
        flash('You are not enrolled in this class', 'danger')
        return redirect(url_for('student_dashboard'))
    
    class_obj = Class.query.get_or_404(class_id)
    sessions = AttendanceSession.query.filter_by(class_id=class_id, is_active=False).order_by(AttendanceSession.date.desc()).all()
    
    records = []
    for session in sessions:
        record = AttendanceRecord.query.filter_by(session_id=session.id, student_id=current_user.id).first()
        records.append({
            'session': session,
            'status': record.status if record else 'N/A'
        })
    
    return render_template('student_history.html', class_obj=class_obj, records=records)

@app.route('/teacher/session/<int:session_id>/edit_record', methods=['POST'])
@login_required
@teacher_required
def edit_attendance_record(session_id):
    session_obj = AttendanceSession.query.get_or_404(session_id)
    class_obj = session_obj.class_ref
    
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    student_id = request.form.get('student_id', type=int)
    new_status = request.form.get('status')
    
    record = AttendanceRecord.query.filter_by(session_id=session_id, student_id=student_id).first()
    
    if record:
        record.status = new_status
    else:
        record = AttendanceRecord(session_id=session_id, student_id=student_id, status=new_status)
        db.session.add(record)
    
    db.session.commit()
    flash('Attendance record updated', 'success')
    return redirect(url_for('view_session', session_id=session_id))

@app.route('/teacher/class/<int:class_id>/student/<int:student_id>/history')
@login_required
@teacher_required
def student_attendance_history(class_id, student_id):
    class_obj = Class.query.get_or_404(class_id)

    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))

    student = User.query.get_or_404(student_id)

    # Check if student is enrolled
    enrollment = Enrollment.query.filter_by(class_id=class_id, student_id=student_id).first()
    if not enrollment:
        flash('Student is not enrolled in this class', 'danger')
        return redirect(url_for('view_class', class_id=class_id))

    # Get all sessions for this class
    sessions = AttendanceSession.query.filter_by(class_id=class_id, is_active=False).order_by(AttendanceSession.date.desc()).all()

    # Get attendance records for this student
    attendance_data = []
    present_count = 0
    late_count = 0
    absent_count = 0

    for session in sessions:
        record = AttendanceRecord.query.filter_by(session_id=session.id, student_id=student_id).first()
        status = record.status if record else 'Absent'

        if status == 'Present':
            present_count += 1
        elif status == 'Late':
            late_count += 1
        else:
            absent_count += 1

        attendance_data.append({
            'session': session,
            'status': status,
            'timestamp': record.timestamp if record else None
        })

    total_sessions = len(sessions)
    attendance_rate = ((present_count + late_count) / total_sessions * 100) if total_sessions > 0 else 0

    return render_template('teacher_student_history.html',
                         class_obj=class_obj,
                         student=student,
                         attendance_data=attendance_data,
                         total_sessions=total_sessions,
                         present_count=present_count,
                         late_count=late_count,
                         absent_count=absent_count,
                         attendance_rate=round(attendance_rate, 1))

@app.route('/teacher/class/<int:class_id>/export')
@login_required
@teacher_required
def export_attendance(class_id):
    class_obj = Class.query.get_or_404(class_id)
    
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['Student Name', 'Student ID', 'Email', 'Date', 'Status'])
    
    # Get all sessions
    sessions = AttendanceSession.query.filter_by(class_id=class_id).order_by(AttendanceSession.date).all()
    
    for session in sessions:
        records = AttendanceRecord.query.filter_by(session_id=session.id).all()
        for record in records:
            student = record.student
            writer.writerow([
                student.name,
                student.student_id or 'N/A',
                student.email,
                session.date.strftime('%Y-%m-%d %H:%M'),
                record.status
            ])
    
    # Prepare response
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'{class_obj.code}_attendance.csv'
    )

# Initialize database tables
with app.app_context():
    db.create_all()

# For Vercel deployment
app = app

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
import pytz
import secrets
import qrcode
import io
import csv
from functools import wraps
import os
import re
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler

# Load environment variables from .env file
load_dotenv()

# Eastern timezone
EASTERN = pytz.timezone('US/Eastern')

def get_eastern_time():
    """Get current time in Eastern timezone"""
    return datetime.now(EASTERN)

app = Flask(__name__)

# Configuration - Always use environment variables
# SECRET_KEY is required in .env file
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    # Generate a temporary key for testing only (NOT for production)
    if os.environ.get('FLASK_ENV') == 'production':
        raise ValueError("❌ DEPLOYMENT ERROR: SECRET_KEY environment variable is required!\n"
                        "Please set SECRET_KEY in your deployment platform's environment variables.\n"
                        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
    else:
        app.config['SECRET_KEY'] = 'dev-key-not-for-production'

# DATABASE_URL is required in .env file (Supabase PostgreSQL)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
if not app.config['SQLALCHEMY_DATABASE_URI']:
    if os.environ.get('FLASK_ENV') == 'production':
        raise ValueError("❌ DEPLOYMENT ERROR: DATABASE_URL environment variable is required!\n"
                        "Please set DATABASE_URL in your deployment platform's environment variables.\n"
                        "Use Supabase Connection Pooling URL (port 6543, not 5432).")
    else:
        # For development, use a dummy value (will fail if app tries to connect to DB)
        app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://dummy:dummy@localhost/dummy'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') != 'development'  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # Session timeout
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF tokens don't expire with session

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Use Redis in production for distributed systems
)

# Initialize security headers (only enforce HTTPS in production)
if os.environ.get('FLASK_ENV') != 'development':
    Talisman(app,
        force_https=True,
        strict_transport_security=True,
        content_security_policy={
            'default-src': "'self'",
            'script-src': ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
            'style-src': ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
            'img-src': ["'self'", "data:", "https:"],
            'font-src': ["'self'", "cdnjs.cloudflare.com"]
        }
    )
else:
    # Add basic security headers even in development
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

# ============================================
# Logging Configuration
# ============================================
if not app.debug and not app.testing:
    # Production logging to file (only if not on serverless platform like Vercel)
    is_serverless = os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
    
    if not is_serverless:
        # File logging only on traditional servers
        try:
            if not os.path.exists('logs'):
                os.mkdir('logs')
            
            file_handler = RotatingFileHandler(
                'logs/rollcallqr.log',
                maxBytes=10240000,  # 10MB
                backupCount=10      # Keep 10 backup files
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
        except (OSError, IOError) as e:
            # If we can't create logs directory (e.g., on serverless), skip file logging
            app.logger.warning('Could not create log file: {}'.format(e))
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('==========================================')
    app.logger.info('RollCallQR Application Startup')
    app.logger.info('Environment: {}'.format(os.environ.get('FLASK_ENV', 'development')))
    app.logger.info('Platform: {}'.format('Vercel' if os.environ.get('VERCEL') else 'Traditional'))
    app.logger.info('==========================================')

# ============================================
# Email Configuration (Flask-Mail)
# ============================================
# Email settings for password resets and notifications
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@rollcallqr.com')

# Initialize Flask-Mail
mail = Mail(app)

# Email helper function
def send_password_reset_email(user_email, reset_url):
    """Send password reset email to user"""
    try:
        msg = Message(
            subject='RollCallQR - Password Reset Request',
            recipients=[user_email],
            html=f"""
            <html style="font-family: Arial, sans-serif; background-color: #f5f5f5;">
                <body style="margin: 0; padding: 20px;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        <div style="text-align: center; margin-bottom: 30px;">
                            <h1 style="color: #0066cc; margin: 0; font-size: 24px;">RollCallQR</h1>
                            <p style="color: #666; margin: 5px 0 0 0; font-size: 14px;">Attendance Tracking System</p>
                        </div>
                        
                        <h2 style="color: #333; margin-bottom: 20px;">Password Reset Request</h2>
                        
                        <p style="color: #666; line-height: 1.6; margin-bottom: 20px;">
                            Hello,<br><br>
                            You requested a password reset for your RollCallQR account. 
                            Click the button below to reset your password. This link will expire in 1 hour.
                        </p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{reset_url}" style="background-color: #0066cc; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">
                                Reset Password
                            </a>
                        </div>
                        
                        <p style="color: #999; font-size: 14px; margin: 20px 0; border-top: 1px solid #eee; padding-top: 20px;">
                            If you didn't request this, you can ignore this email. Your password won't change unless you click the link above.
                        </p>
                        
                        <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px;">
                            © 2025 RollCallQR. All rights reserved.
                        </p>
                    </div>
                </body>
            </html>
            """,
            text_body=f"""
            Password Reset Request
            
            You requested a password reset. Click the link below to reset your password (expires in 1 hour):
            
            {reset_url}
            
            If you didn't request this, ignore this email.
            """
        )
        mail.send(msg)
        app.logger.info(f'Password reset email sent to {user_email}')
        return True
    except Exception as e:
        app.logger.error(f'Failed to send password reset email to {user_email}: {str(e)}')
        return False

# ============================================
# Database Models
# ============================================
class PendingStudent(db.Model):
    """Students added to classes by teachers before they register"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100))  # Optional name provided by teacher
    added_by_teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=get_eastern_time)
    
    # Make email lowercase when setting
    def __init__(self, **kwargs):
        if 'email' in kwargs:
            kwargs['email'] = kwargs['email'].lower()
        super(PendingStudent, self).__init__(**kwargs)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'teacher' or 'student'
    student_id = db.Column(db.String(50))  # Only for students
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = get_eastern_time() + timedelta(hours=1)
        return self.reset_token

    def verify_reset_token(self, token):
        if self.reset_token == token and self.reset_token_expiry > get_eastern_time():
            return True
        return False

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
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for pending students
    student_email = db.Column(db.String(100), nullable=True)  # For pending students who haven't registered
    student_name = db.Column(db.String(100), nullable=True)  # Optional name for pending students
    enrollment_date = db.Column(db.DateTime, default=get_eastern_time)
    class_ref = db.relationship('Class', backref='enrollments')
    student = db.relationship('User', backref='enrollments', foreign_keys=[student_id])
    
    # Make email lowercase when setting
    def __init__(self, **kwargs):
        if 'student_email' in kwargs and kwargs['student_email']:
            kwargs['student_email'] = kwargs['student_email'].lower()
        super(Enrollment, self).__init__(**kwargs)

class AttendanceSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
    date = db.Column(db.DateTime, default=get_eastern_time)
    qr_token = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    class_ref = db.relationship('Class', backref='sessions')

class AttendanceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('attendance_session.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for pending students
    student_email = db.Column(db.String(100), nullable=True)  # For pending students
    status = db.Column(db.String(20), nullable=False)  # 'Present', 'Late', or 'Absent'
    timestamp = db.Column(db.DateTime, default=get_eastern_time)
    session = db.relationship('AttendanceSession', backref='records')
    student = db.relationship('User', backref='attendance_records', foreign_keys=[student_id])
    
    # Make email lowercase when setting
    def __init__(self, **kwargs):
        if 'student_email' in kwargs and kwargs['student_email']:
            kwargs['student_email'] = kwargs['student_email'].lower()
        super(AttendanceRecord, self).__init__(**kwargs)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Validation helper functions
def validate_password(password):
    """Validate password strength"""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not email or not re.match(pattern, email):
        return False, "Invalid email format"
    return True, ""

def validate_name(name):
    """Validate name field"""
    if not name or len(name.strip()) == 0:
        return False, "Name is required"
    if len(name) > 100:
        return False, "Name is too long (maximum 100 characters)"
    return True, ""

def validate_class_code(code):
    """Validate class code format"""
    if not code or len(code.strip()) == 0:
        return False, "Class code is required"
    if len(code) > 20:
        return False, "Class code is too long (maximum 20 characters)"
    if not re.match(r'^[A-Za-z0-9_-]+$', code):
        return False, "Class code can only contain letters, numbers, hyphens, and underscores"
    return True, ""

def validate_text_length(text, field_name, max_length=500):
    """Validate text field length"""
    if text and len(text) > max_length:
        return False, f"{field_name} is too long (maximum {max_length} characters)"
    return True, ""

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
def login_user_check():
    return User.query.first() is not None

# Health check endpoint for monitoring and uptime services
@app.route('/health', methods=['GET'])
@csrf.exempt  # Exempt from CSRF protection for monitoring services
def health_check():
    """
    Health check endpoint for uptime monitoring.
    Returns status and basic health metrics.
    """
    try:
        # Check database connection
        db.session.execute(db.text('SELECT 1'))
        db_status = 'healthy'
    except Exception as e:
        db_status = f'error: {str(e)}'
    
    health_status = {
        'status': 'healthy' if db_status == 'healthy' else 'degraded',
        'timestamp': get_eastern_time().isoformat(),
        'database': db_status,
        'environment': os.environ.get('FLASK_ENV', 'development')
    }
    
    return jsonify(health_status), 200 if db_status == 'healthy' else 503

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit: max 5 login attempts per minute
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False) == 'on'

        # Validate email format
        is_valid, msg = validate_email(email)
        if not is_valid:
            flash(msg, 'danger')
            return render_template('login.html')

        # Case-insensitive email search
        user = User.query.filter(db.func.lower(User.email) == email).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("15 per hour")  # Rate limit: max 15 registrations per hour per IP (reasonable for legitimate users)
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '').strip().lower()  # Normalize email to lowercase
        password = request.form.get('password', '')
        role = request.form.get('role', '')
        student_id = request.form.get('student_id', '')

        # Validate name
        is_valid, msg = validate_name(name)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('register'))

        # Validate email format
        is_valid, msg = validate_email(email)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('register'))

        # Validate password strength
        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('register'))

        # Validate role
        if role not in ['teacher', 'student']:
            flash('Invalid role selected', 'danger')
            return redirect(url_for('register'))

        # Validate student_id length if provided
        if student_id and len(student_id) > 50:
            flash('Student ID is too long (maximum 50 characters)', 'danger')
            return redirect(url_for('register'))

        # Check if email already exists (case-insensitive)
        if User.query.filter(db.func.lower(User.email) == email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        user = User(name=name, email=email, role=role, student_id=student_id)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()  # Get the user ID without committing
        
        # If registering as a student, check for pending enrollments and attendance
        if role == 'student':
            # Find all enrollments with this email (pending students)
            pending_enrollments = Enrollment.query.filter(
                db.func.lower(Enrollment.student_email) == email,
                Enrollment.student_id.is_(None)
            ).all()
            
            classes_connected = []
            for enrollment in pending_enrollments:
                enrollment.student_id = user.id
                enrollment.student_email = None  # Clear email since we have student_id now
                classes_connected.append(enrollment.class_ref.name)
            
            # Update attendance records with this email to link to the new user
            pending_records = AttendanceRecord.query.filter(
                db.func.lower(AttendanceRecord.student_email) == email,
                AttendanceRecord.student_id.is_(None)
            ).all()
            
            for record in pending_records:
                record.student_id = user.id
                record.student_email = None
            
            # Delete pending student record if exists
            PendingStudent.query.filter(db.func.lower(PendingStudent.email) == email).delete()
        
        db.session.commit()
        
        if role == 'student' and classes_connected:
            flash(f'Registration successful! You have been automatically enrolled in: {", ".join(classes_connected)}', 'success')
        else:
            flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    # Check if there's a suggested email from query params (for pending students)
    suggested_email = request.args.get('email', '')
    
    return render_template('register.html', suggested_email=suggested_email)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")  # Rate limit: max 3 password reset requests per hour
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        # Validate email format
        is_valid, msg = validate_email(email)
        if not is_valid:
            flash(msg, 'danger')
            return render_template('forgot_password.html')

        user = User.query.filter(db.func.lower(User.email) == email).first()

        if user:
            token = user.generate_reset_token()
            db.session.commit()

            # Generate reset URL
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Try to send email
            email_sent = send_password_reset_email(user.email, reset_url)
            
            if email_sent:
                flash('Password reset link has been sent to your email. Check your inbox or spam folder.', 'success')
                app.logger.info(f'Password reset email sent to {user.email}')
            else:
                # Fallback: If email fails, show warning but still allow password reset
                flash('Password reset link generated. Email system is currently unavailable.', 'warning')
                app.logger.warning(f'Failed to send password reset email to {user.email}')
        else:
            # Don't reveal if email exists or not for security
            flash('If that email exists, a password reset link has been sent.', 'info')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Rate limit: max 5 password reset attempts per hour
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.verify_reset_token(token):
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        # Validate password strength
        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg, 'danger')
            return render_template('reset_password.html', token=token)

        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()

        flash('Your password has been reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

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
        name = request.form.get('name', '')
        code = request.form.get('code', '')
        description = request.form.get('description', '')

        # Validate class name
        is_valid, msg = validate_name(name)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('add_class'))

        # Validate class code
        is_valid, msg = validate_class_code(code)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('add_class'))

        # Validate description length
        is_valid, msg = validate_text_length(description, "Description", max_length=1000)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('add_class'))

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
    
    # Separate registered students and pending students
    students = []
    pending_students = []
    
    for e in enrollments:
        if e.student_id:
            # Registered student
            students.append({
                'enrollment': e,
                'user': e.student,
                'is_pending': False
            })
        else:
            # Pending student (only has email)
            pending_students.append({
                'enrollment': e,
                'email': e.student_email,
                'name': e.student_name,  # May be None
                'is_pending': True
            })
    
    # Combine them
    all_students = students + pending_students
    
    sessions = AttendanceSession.query.filter_by(class_id=class_id).order_by(AttendanceSession.date.desc()).all()
    
    return render_template('view_class.html', class_obj=class_obj, students=all_students, sessions=sessions)

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
        email = request.form.get('email').strip().lower()
        name = request.form.get('name', '').strip()  # Optional name
        
        # Check if already enrolled (either as registered or pending student)
        existing = Enrollment.query.filter(
            Enrollment.class_id == class_id,
            db.or_(
                db.func.lower(Enrollment.student_email) == email,
                Enrollment.student_id.in_(
                    db.session.query(User.id).filter(db.func.lower(User.email) == email)
                )
            )
        ).first()
        
        if existing:
            flash('This email is already enrolled in this class.', 'warning')
            return redirect(url_for('view_class', class_id=class_id))
        
        # Check if student is registered
        student = User.query.filter(
            db.func.lower(User.email) == email,
            User.role == 'student'
        ).first()
        
        if student:
            # Student is registered, create enrollment with student_id
            enrollment = Enrollment(class_id=class_id, student_id=student.id)
            db.session.add(enrollment)
            db.session.commit()
            flash(f'{student.name} added to class!', 'success')
        else:
            # Student not registered yet, create pending enrollment with email and optional name
            enrollment = Enrollment(class_id=class_id, student_email=email, student_name=name if name else None)
            db.session.add(enrollment)
            
            # Also create a pending student record for tracking
            pending = PendingStudent.query.filter(db.func.lower(PendingStudent.email) == email).first()
            if not pending:
                pending = PendingStudent(email=email, name=name if name else None, added_by_teacher_id=current_user.id)
                db.session.add(pending)
            elif name and not pending.name:
                # Update name if provided and not already set
                pending.name = name
            
            db.session.commit()
            display_name = name if name else email
            flash(f'{display_name} added to class. They can check in with this email and will be automatically enrolled when they register.', 'info')
        
        return redirect(url_for('view_class', class_id=class_id))
    
    return render_template('add_student.html', class_obj=class_obj)

@app.route('/teacher/class/<int:class_id>/bulk_upload', methods=['POST'])
@login_required
@teacher_required
def bulk_upload_students(class_id):
    """Bulk upload students from CSV file"""
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    if 'file' not in request.files:
        flash('No file provided', 'danger')
        return redirect(url_for('view_class', class_id=class_id))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('view_class', class_id=class_id))
    
    if not file.filename.endswith(('.csv', '.xlsx', '.txt')):
        flash('Please upload a CSV, Excel, or text file', 'danger')
        return redirect(url_for('view_class', class_id=class_id))
    
    try:
        # Read CSV content
        stream = io.StringIO(file.stream.read().decode('utf-8'), newline=None)
        csv_reader = csv.reader(stream)
        
        # Get headers
        headers = next(csv_reader, None)
        if not headers:
            flash('CSV file is empty', 'danger')
            return redirect(url_for('view_class', class_id=class_id))
        
        # Normalize headers to lowercase
        headers = [h.strip().lower() for h in headers]
        
        # Find column indices
        email_idx = None
        name_idx = None
        student_id_idx = None
        
        for idx, header in enumerate(headers):
            if 'email' in header:
                email_idx = idx
            elif 'name' in header:
                name_idx = idx
            elif 'student' in header and 'id' in header:
                student_id_idx = idx
        
        if email_idx is None:
            flash('CSV must contain an "email" column', 'danger')
            return redirect(url_for('view_class', class_id=class_id))
        
        added_count = 0
        skipped_count = 0
        error_rows = []
        
        for row_num, row in enumerate(csv_reader, start=2):
            if not row or all(not cell.strip() for cell in row):
                continue
            
            try:
                email = row[email_idx].strip().lower() if email_idx < len(row) else ''
                name = row[name_idx].strip() if name_idx and name_idx < len(row) else ''
                student_id = row[student_id_idx].strip() if student_id_idx and student_id_idx < len(row) else ''
                
                if not email:
                    error_rows.append(f"Row {row_num}: Missing email")
                    skipped_count += 1
                    continue
                
                # Validate email format
                is_valid, msg = validate_email(email)
                if not is_valid:
                    error_rows.append(f"Row {row_num}: {msg}")
                    skipped_count += 1
                    continue
                
                # Check if already enrolled
                existing = Enrollment.query.filter(
                    Enrollment.class_id == class_id,
                    db.or_(
                        db.func.lower(Enrollment.student_email) == email,
                        Enrollment.student_id.in_(
                            db.session.query(User.id).filter(db.func.lower(User.email) == email)
                        )
                    )
                ).first()
                
                if existing:
                    error_rows.append(f"Row {row_num}: {email} already enrolled")
                    skipped_count += 1
                    continue
                
                # Check if student is registered
                student = User.query.filter(
                    db.func.lower(User.email) == email,
                    User.role == 'student'
                ).first()
                
                if student:
                    # Student is registered, create enrollment with student_id
                    enrollment = Enrollment(class_id=class_id, student_id=student.id)
                    db.session.add(enrollment)
                else:
                    # Student not registered yet, create pending enrollment
                    enrollment = Enrollment(
                        class_id=class_id,
                        student_email=email,
                        student_name=name if name else None
                    )
                    db.session.add(enrollment)
                    
                    # Create or update pending student record
                    pending = PendingStudent.query.filter(db.func.lower(PendingStudent.email) == email).first()
                    if not pending:
                        pending = PendingStudent(
                            email=email,
                            name=name if name else None,
                            added_by_teacher_id=current_user.id
                        )
                        db.session.add(pending)
                    elif name and not pending.name:
                        pending.name = name
                
                added_count += 1
            
            except Exception as e:
                error_rows.append(f"Row {row_num}: {str(e)}")
                skipped_count += 1
                continue
        
        db.session.commit()
        
        # Build success message
        message = f'Successfully added {added_count} student(s)'
        if skipped_count > 0:
            message += f'. {skipped_count} row(s) skipped.'
            if error_rows and len(error_rows) <= 5:
                message += ' Errors: ' + '; '.join(error_rows[:5])
            elif error_rows:
                message += f' (First 5 errors: ' + '; '.join(error_rows[:5]) + ')'
        
        flash(message, 'success' if added_count > 0 else 'warning')
    
    except Exception as e:
        flash(f'Error processing file: {str(e)}', 'danger')
    
    return redirect(url_for('view_class', class_id=class_id))

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

@app.route('/teacher/class/<int:class_id>/remove_pending_student', methods=['POST'])
@login_required
@teacher_required
def remove_pending_student(class_id):
    class_obj = Class.query.get_or_404(class_id)
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    email = request.form.get('email')
    enrollment = Enrollment.query.filter(
        Enrollment.class_id == class_id,
        db.func.lower(Enrollment.student_email) == email.lower()
    ).first()
    
    if enrollment:
        db.session.delete(enrollment)
        db.session.commit()
        flash('Pending student removed from class.', 'success')
    
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
    
    # Get client timestamp if provided
    client_timestamp_str = request.form.get('client_timestamp', '')
    client_timestamp = None
    if client_timestamp_str:
        try:
            # Parse ISO format timestamp from client (it's in UTC from toISOString())
            utc_dt = datetime.fromisoformat(client_timestamp_str.replace('Z', '+00:00'))
            # Convert UTC to Eastern timezone
            eastern_dt = utc_dt.astimezone(EASTERN)
            # Remove timezone info to store as naive datetime in database
            client_timestamp = eastern_dt.replace(tzinfo=None)
        except (ValueError, AttributeError):
            # If parsing fails, will use server time
            pass
    
    # Create new session with client timestamp
    token = secrets.token_urlsafe(16)
    session_obj = AttendanceSession(
        class_id=class_id, 
        qr_token=token,
        date=client_timestamp if client_timestamp else get_eastern_time()
    )
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
    present_students = set()
    
    for r in records:
        if r.status == 'Present':
            if r.student_id:
                present_students.add(r.student_id)
            else:
                present_students.add(r.student_email)
    
    enrollments = Enrollment.query.filter_by(class_id=class_obj.id).all()
    
    # Build list of all students (registered and pending)
    all_students = []
    for e in enrollments:
        if e.student_id:
            all_students.append({
                'user': e.student,
                'email': e.student.email,
                'name': e.student.name,
                'is_pending': False,
                'enrollment': e
            })
        else:
            all_students.append({
                'user': None,
                'email': e.student_email,
                'name': e.student_name,  # May be None
                'is_pending': True,
                'enrollment': e
            })
    
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
    
    # Get all enrolled students (registered and pending)
    enrollments = Enrollment.query.filter_by(class_id=class_obj.id).all()
    
    # Mark absent students with client-side timestamp
    client_timestamp_str = request.form.get('client_timestamp', '')
    client_timestamp = None
    if client_timestamp_str:
        try:
            # Parse ISO format timestamp from client (it's in UTC from toISOString())
            utc_dt = datetime.fromisoformat(client_timestamp_str.replace('Z', '+00:00'))
            # Convert UTC to Eastern timezone
            eastern_dt = utc_dt.astimezone(EASTERN)
            # Remove timezone info to store as naive datetime in database
            client_timestamp = eastern_dt.replace(tzinfo=None)
        except (ValueError, AttributeError):
            # If parsing fails, will use server time
            pass
    
    for enrollment in enrollments:
        existing_record = None
        
        if enrollment.student_id:
            # Registered student
            existing_record = AttendanceRecord.query.filter_by(
                session_id=session_id, 
                student_id=enrollment.student_id
            ).first()
            
            if not existing_record:
                absent_record = AttendanceRecord(
                    session_id=session_id,
                    student_id=enrollment.student_id,
                    status='Absent',
                    timestamp=client_timestamp if client_timestamp else get_eastern_time()
                )
                db.session.add(absent_record)
        else:
            # Pending student (email only)
            existing_record = AttendanceRecord.query.filter(
                AttendanceRecord.session_id == session_id,
                db.func.lower(AttendanceRecord.student_email) == enrollment.student_email.lower()
            ).first()
            
            if not existing_record:
                absent_record = AttendanceRecord(
                    session_id=session_id,
                    student_email=enrollment.student_email,
                    status='Absent',
                    timestamp=client_timestamp if client_timestamp else get_eastern_time()
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
    # No cache headers to ensure fresh QR is generated on each request
    response = send_file(
        img_io,
        mimetype='image/png',
        as_attachment=False,
        download_name=f'qr_session_{session_id}.png'
    )
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

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
        email = request.form.get('email').strip().lower()
        client_timestamp_str = request.form.get('client_timestamp', '')
        
        # Parse client timestamp if provided
        client_timestamp = None
        if client_timestamp_str:
            try:
                # Parse ISO format timestamp from client (it's in UTC from toISOString())
                utc_dt = datetime.fromisoformat(client_timestamp_str.replace('Z', '+00:00'))
                # Convert UTC to Eastern timezone
                eastern_dt = utc_dt.astimezone(EASTERN)
                # Remove timezone info to store as naive datetime in database
                client_timestamp = eastern_dt.replace(tzinfo=None)
            except (ValueError, AttributeError):
                # If parsing fails, will use server time
                pass
        
        # Check if this email is enrolled in the class (either as registered or pending student)
        enrollment = Enrollment.query.filter(
            Enrollment.class_id == session_obj.class_id,
            db.or_(
                db.func.lower(Enrollment.student_email) == email,
                Enrollment.student_id.in_(
                    db.session.query(User.id).filter(
                        db.func.lower(User.email) == email,
                        User.role == 'student'
                    )
                )
            )
        ).first()

        if not enrollment:
            flash('This email is not enrolled in this class. Please contact your teacher.', 'danger')
            return render_template('check_in.html', session=session_obj, token=token)
        
        # Check if student is registered
        student = User.query.filter(
            db.func.lower(User.email) == email,
            User.role == 'student'
        ).first()

        # Check if already checked in (check both student_id and email)
        existing_record = None
        if student:
            existing_record = AttendanceRecord.query.filter_by(
                session_id=session_obj.id,
                student_id=student.id
            ).first()
        else:
            existing_record = AttendanceRecord.query.filter(
                AttendanceRecord.session_id == session_obj.id,
                db.func.lower(AttendanceRecord.student_email) == email
            ).first()

        if existing_record:
            flash('You have already checked in for this session', 'info')
            return render_template('check_in.html', session=session_obj, token=token, success=True)

        # Create attendance record with client timestamp
        if student:
            # Registered student
            record = AttendanceRecord(
                session_id=session_obj.id,
                student_id=student.id,
                status='Present',
                timestamp=client_timestamp if client_timestamp else get_eastern_time()
            )
        else:
            # Pending student (not registered yet)
            record = AttendanceRecord(
                session_id=session_obj.id,
                student_email=email,
                status='Present',
                timestamp=client_timestamp if client_timestamp else get_eastern_time()
            )
        
        db.session.add(record)
        db.session.commit()

        if student:
            flash(f'✓ Attendance marked for {session_obj.class_ref.name}!', 'success')
        else:
            flash(f'✓ Attendance marked for {session_obj.class_ref.name}! Register with this email to track your full attendance history.', 'success')
        
        return render_template('check_in.html', session=session_obj, token=token, success=True, suggest_register=not student, email=email)

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
    student_email = request.form.get('student_email')
    new_status = request.form.get('status')
    
    record = None
    
    if student_id:
        # Registered student
        record = AttendanceRecord.query.filter_by(session_id=session_id, student_id=student_id).first()
        
        if record:
            record.status = new_status
        else:
            record = AttendanceRecord(session_id=session_id, student_id=student_id, status=new_status)
            db.session.add(record)
    elif student_email:
        # Pending student
        record = AttendanceRecord.query.filter(
            AttendanceRecord.session_id == session_id,
            db.func.lower(AttendanceRecord.student_email) == student_email.lower()
        ).first()
        
        if record:
            record.status = new_status
        else:
            record = AttendanceRecord(session_id=session_id, student_email=student_email, status=new_status)
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
                         attendance_rate=round(attendance_rate, 1),
                         is_pending=False)

@app.route('/teacher/class/<int:class_id>/pending_student/<email>/history')
@login_required
@teacher_required
def pending_student_attendance_history(class_id, email):
    class_obj = Class.query.get_or_404(class_id)

    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))

    # Decode email from URL
    email = email.lower()

    # Check if pending student is enrolled
    enrollment = Enrollment.query.filter(
        Enrollment.class_id == class_id,
        db.func.lower(Enrollment.student_email) == email
    ).first()

    if not enrollment:
        flash('This email is not enrolled in this class', 'danger')
        return redirect(url_for('view_class', class_id=class_id))

    # Get all sessions for this class
    sessions = AttendanceSession.query.filter_by(class_id=class_id, is_active=False).order_by(AttendanceSession.date.desc()).all()

    # Get attendance records for this pending student
    attendance_data = []
    present_count = 0
    late_count = 0
    absent_count = 0

    for session in sessions:
        record = AttendanceRecord.query.filter(
            AttendanceRecord.session_id == session.id,
            db.func.lower(AttendanceRecord.student_email) == email
        ).first()
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

    # Create a student-like object for the template
    student_info = {
        'name': enrollment.student_name if enrollment.student_name else 'Not Registered',
        'email': email,
        'student_id': None
    }

    return render_template('teacher_student_history.html',
                         class_obj=class_obj,
                         student=student_info,
                         attendance_data=attendance_data,
                         total_sessions=total_sessions,
                         present_count=present_count,
                         late_count=late_count,
                         absent_count=absent_count,
                         attendance_rate=round(attendance_rate, 1),
                         is_pending=True)

@app.route('/teacher/class/<int:class_id>/attendance_report')
@login_required
@teacher_required
def class_attendance_report(class_id):
    """Show overall attendance report for all students in a class"""
    class_obj = Class.query.get_or_404(class_id)
    
    if class_obj.teacher_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    # Get all sessions for this class
    sessions = AttendanceSession.query.filter_by(class_id=class_id, is_active=False).order_by(AttendanceSession.date.desc()).all()
    total_sessions = len(sessions)
    
    if total_sessions == 0:
        flash('No completed sessions yet for this class', 'info')
        return redirect(url_for('view_class', class_id=class_id))
    
    # Get all students and their enrollment in this class
    enrollments = Enrollment.query.filter_by(class_id=class_id).all()
    
    # Build student attendance summary
    student_stats = []
    
    # Add registered students
    for enrollment in enrollments:
        if enrollment.student_id:
            # Registered student
            student = User.query.get(enrollment.student_id)
            if student:
                present_count = 0
                late_count = 0
                absent_count = 0
                
                for session in sessions:
                    record = AttendanceRecord.query.filter_by(session_id=session.id, student_id=student.id).first()
                    status = record.status if record else 'Absent'
                    
                    if status == 'Present':
                        present_count += 1
                    elif status == 'Late':
                        late_count += 1
                    else:
                        absent_count += 1
                
                attendance_rate = ((present_count + late_count) / total_sessions * 100) if total_sessions > 0 else 0
                
                student_stats.append({
                    'name': student.name,
                    'email': student.email,
                    'student_id': student.student_id,
                    'status': 'Registered',
                    'present_count': present_count,
                    'late_count': late_count,
                    'absent_count': absent_count,
                    'attendance_rate': round(attendance_rate, 1),
                    'user_id': student.id
                })
    
    # Add pending students (not yet registered)
    pending_emails = set()
    for enrollment in enrollments:
        if not enrollment.student_id and enrollment.student_email:
            pending_emails.add(enrollment.student_email.lower())
    
    for email in pending_emails:
        present_count = 0
        late_count = 0
        absent_count = 0
        pending_student_name = None
        
        for session in sessions:
            record = AttendanceRecord.query.filter(
                AttendanceRecord.session_id == session.id,
                db.func.lower(AttendanceRecord.student_email) == email
            ).first()
            status = record.status if record else 'Absent'
            
            if status == 'Present':
                present_count += 1
            elif status == 'Late':
                late_count += 1
            else:
                absent_count += 1
        
        # Get pending student name if available
        for enrollment in enrollments:
            if enrollment.student_email and enrollment.student_email.lower() == email:
                pending_student_name = enrollment.student_name if enrollment.student_name else 'Not Registered'
                break
        
        attendance_rate = ((present_count + late_count) / total_sessions * 100) if total_sessions > 0 else 0
        
        student_stats.append({
            'name': pending_student_name or 'Not Registered',
            'email': email,
            'student_id': None,
            'status': 'Pending',
            'present_count': present_count,
            'late_count': late_count,
            'absent_count': absent_count,
            'attendance_rate': round(attendance_rate, 1),
            'user_id': None
        })
    
    # Sort by attendance rate descending
    student_stats.sort(key=lambda x: x['attendance_rate'], reverse=True)
    
    return render_template('class_attendance_report.html',
                         class_obj=class_obj,
                         student_stats=student_stats,
                         total_sessions=total_sessions)

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
    writer.writerow(['Student Name', 'Student ID', 'Email', 'Registration Status', 'Date', 'Status'])
    
    # Get all sessions
    sessions = AttendanceSession.query.filter_by(class_id=class_id).order_by(AttendanceSession.date).all()
    
    for session in sessions:
        records = AttendanceRecord.query.filter_by(session_id=session.id).all()
        for record in records:
            if record.student_id:
                # Registered student
                student = record.student
                writer.writerow([
                    student.name,
                    student.student_id or 'N/A',
                    student.email,
                    'Registered',
                    session.date.strftime('%Y-%m-%d %H:%M'),
                    record.status
                ])
            else:
                # Pending student
                writer.writerow([
                    'Not Registered',
                    'N/A',
                    record.student_email,
                    'Pending',
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

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error_code=403, error_message="Access denied"), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # Rollback any failed database transactions
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(429)
def ratelimit_handler(error):
    return render_template('error.html', error_code=429, error_message="Too many requests. Please try again later."), 429

# Initialize database tables
with app.app_context():
    db.create_all()

# Production entry point
if __name__ == '__main__':
    # Determine environment and configuration 

    env = os.environ.get('FLASK_ENV', 'development')
    debug_mode = env == 'development'
    port = int(os.environ.get('PORT', 5000))
    
    # Log startup information
    print('╔════════════════════════════════════════╗')
    print('║         RollCallQR - Starting          ║')
    print('╠════════════════════════════════════════╣')
    print(f'║ Environment: {env.upper():<30}║')
    print(f'║ Debug Mode: {"ON" if debug_mode else "OFF":<33}║')
    print(f'║ Port: {port:<34}║')
    print(f'║ Database: {"Configured" if app.config.get("SQLALCHEMY_DATABASE_URI") else "NOT SET":<28}║')
    print(f'║ Email: {"Configured" if app.config.get("MAIL_USERNAME") else "NOT CONFIGURED":<29}║')
    print('╚════════════════════════════════════════╝')
    
    # Development settings
    if debug_mode:
        print('⚠️  DEVELOPMENT MODE - Do not use in production!')
        print('📧 Email will show in console during testing')
        print('🔍 Debug toolbar enabled')
        print('💡 TIP: Run with `python app.py` for development')
        
        # For development, print reset links to console instead of sending emails
        original_send = mail.send
        def debug_send(message):
            print(f'\n✉️  EMAIL WOULD BE SENT TO: {message.recipients}')
            print(f'   SUBJECT: {message.subject}')
            return original_send(message)
        mail.send = debug_send
    else:
        print('✅ PRODUCTION MODE')
        print('📧 Emails will be sent via SMTP')
        print('🔐 Security headers enabled')
        print('💡 TIP: Run with `gunicorn app:app` for production')
    
    # Run the application
    try:
        app.run(
            debug=debug_mode,
            host='0.0.0.0',  # Listen on all interfaces (required for deployment)
            port=port,
            use_reloader=debug_mode  # Only use reloader in development
        )
    except KeyboardInterrupt:
        print('\n\n🛑 Application shutdown requested')
    except Exception as e:
        print(f'\n\n❌ Application error: {e}')
        raise
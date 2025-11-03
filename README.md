# Teaching Management System

A modern, professional web-based attendance management system built with Flask. Features QR code-based attendance tracking, beautiful UI, and comprehensive management tools for teachers and students.

![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

### For Teachers
- 📚 **Class Management**: Create and manage multiple classes
- 👥 **Student Enrollment**: Add students to classes via email
- 📊 **Attendance Tracking**: Start sessions and track attendance in real-time
- 📱 **QR Code Generation**: Generate unique QR codes for each session
- 📈 **Student History**: View detailed attendance history for individual students
- 📥 **CSV Export**: Export attendance data for record-keeping
- ⏰ **Late Tracking**: Mark students as Present, Late, or Absent
- 🎯 **Session Management**: Open/close sessions and manually adjust records

### For Students
- 📱 **QR Check-in**: Scan QR codes to mark attendance (no login required!)
- 📊 **Dashboard**: View attendance statistics for all enrolled classes
- 📈 **History**: Check detailed attendance history per class
- 🎯 **Attendance Rate**: Track attendance percentage with color-coded indicators
- ✅ **Instant Confirmation**: Beautiful success modal after check-in

### Design Highlights
- 🎨 Modern gradient-based UI with glass-morphism effects
- 🌈 Smooth animations and transitions
- 📱 Fully responsive design (mobile, tablet, desktop)
- ♿ Accessible with proper ARIA labels
- 🎯 Intuitive navigation with Font Awesome icons
- 🔔 Real-time feedback with flash messages
- 💫 Professional status pills and badges

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Supabase account (free tier works great!)

### Installation

1. **Clone or download this project**
   ```bash
   cd flask-attendance-app
   ```

2. **Set up Supabase Database**
   - Create a free account at https://supabase.com
   - Create a new project
   - Get your PostgreSQL connection string from Project Settings > Database
   - Save your database password (you'll need it in step 4)

3. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv

   # On Windows:
   venv\Scripts\activate

   # On macOS/Linux:
   source venv/bin/activate
   ```

4. **Configure environment variables**
   - Copy `.env.example` to `.env`
   - Generate a SECRET_KEY: `python -c "import secrets; print(secrets.token_hex(32))"`
   - Add your Supabase connection string with your password to `DATABASE_URL`

5. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

6. **Initialize the database**
   ```bash
   python init_db.py
   ```

7. **Run the application**
   ```bash
   python app.py
   ```

8. **Open your browser**
   Navigate to `http://127.0.0.1:5000`

## 📱 How to Use

### First Time Setup

1. **Register an account**
   - Go to the registration page
   - Choose "Teacher" or "Student" role
   - Students can optionally provide a Student ID

2. **For Teachers: Create a class**
   - Log in and click "Add New Class"
   - Enter class name (e.g., "Introduction to Computer Science")
   - Enter class code (e.g., "CS101")
   - Add a description (optional)

3. **Add students to your class**
   - Go to the class details page
   - Click "Add Student"
   - Enter the student's registered email address
   - Student must have already registered an account

### Taking Attendance

1. **Start an attendance session**
   - Go to your class page
   - Click "Start Attendance Session"
   - A unique QR code will be generated

2. **Display the QR code**
   - Show the QR code on your screen or projector
   - Students scan the QR code with their phones

3. **Students check in**
   - Students must be logged in to their accounts
   - They scan the QR code using their phone camera or QR scanner app
   - The system automatically marks them present

4. **Close the session**
   - When class ends, click "Close Session"
   - All students who didn't check in are automatically marked absent

5. **Review and edit**
   - View attendance records for each session
   - Manually adjust attendance if needed (after session closes)

### For Students

1. **View your classes**
   - Log in to see all enrolled classes
   - View attendance percentage for each class

2. **Check in to class**
   - When your teacher displays a QR code, scan it
   - You'll receive confirmation of your attendance
   - Must be logged in and enrolled in the class

3. **View attendance history**
   - Click on any class to see detailed attendance records
   - See dates and status for each session

## 📊 Database Structure

The app uses SQLite with the following tables:

- **User**: Stores teacher and student accounts
- **Class**: Course information and teacher assignments
- **Enrollment**: Links students to classes
- **AttendanceSession**: Active and closed attendance sessions
- **AttendanceRecord**: Individual attendance marks

## 🔒 Security Features

- Password hashing using Werkzeug security
- Login required for all attendance actions
- Role-based access control (teacher vs. student)
- Session tokens for QR codes
- Students can only mark their own attendance
- Teachers can only manage their own classes

## 📤 Exporting Data

Teachers can export attendance records as CSV:
1. Go to any class page
2. Click "Export CSV"
3. Opens in spreadsheet software (Excel, Google Sheets)

The CSV includes:
- Student name
- Student ID
- Email
- Date and time of session
- Attendance status

## 🛠️ Project Structure

```
flask-attendance-app/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── attendance.db          # SQLite database (created on first run)
├── templates/             # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── teacher_dashboard.html
│   ├── student_dashboard.html
│   ├── add_class.html
│   ├── edit_class.html
│   ├── view_class.html
│   ├── add_student.html
│   ├── view_session.html
│   └── student_history.html
└── static/
    └── css/
        └── style.css      # Styling
```

## 🎨 Customization

### Change Colors
Edit `static/css/style.css` and modify the CSS variables in `:root`:
```css
:root {
    --primary-color: #2563eb;
    --success-color: #10b981;
    --danger-color: #ef4444;
    /* ... */
}
```

### Add Auto-Close Timer
To automatically close sessions after 5 minutes, you can add a scheduled task using Flask-APScheduler or implement client-side JavaScript countdown.

## 🐛 Troubleshooting

### Database Errors
If you encounter database errors, delete `attendance.db` and restart the app:
```bash
rm attendance.db
python app.py
```

### QR Code Not Scanning
- Ensure you're using the full URL including `http://` or `https://`
- Check that both teacher and student are on the same network
- If deploying online, use proper HTTPS

### Student Can't Check In
- Verify the student is logged in
- Confirm the student is enrolled in the class
- Check that the session is still active
- Ensure the QR code is from the current session

## 🚀 Deployment

### Deploy to Vercel (Recommended)

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/Chris-Buzz/Teaching_Management_System)

**Quick Steps:**
1. Push to GitHub: `git push origin main`
2. Import to [Vercel](https://vercel.com/dashboard)
3. Set environment variables:
   - `SECRET_KEY`: Generate with `python -c "import secrets; print(secrets.token_hex(32))"`
   - `VERCEL_ENV`: `production`
   - `DATABASE_URL`: PostgreSQL URL (optional, recommended for production)
4. Deploy!

**For detailed deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md)**

### Alternative Deployment Options
- Heroku
- PythonAnywhere
- DigitalOcean
- AWS Elastic Beanstalk
- Railway
- Render

## 📝 Example Usage Flow

1. **Teacher (Prof. Smith) creates CS101**
2. **Adds students**: john@university.edu, jane@university.edu
3. **Monday 9:00 AM**: Starts attendance session
4. **Displays QR code** on classroom projector
5. **John scans at 9:05 AM** → Marked present
6. **Jane scans at 9:10 AM** → Marked present
7. **Mike doesn't scan** (forgot or absent)
8. **Monday 9:50 AM**: Prof. Smith closes session
9. **Mike automatically marked absent**
10. **Prof. Smith reviews**: Can manually change Mike to "Present" if needed

## 💡 Tips

- **Keep sessions open** only during class time to prevent false check-ins
- **Close sessions promptly** to mark absentees automatically
- **Export data regularly** for backup and grade calculation
- **Encourage students to register** before the first class
- **Test QR codes** before using them in class

## 📞 Support

For issues or questions:
- Check the troubleshooting section above
- Review Flask documentation: https://flask.palletsprojects.com/
- Review QR code library docs: https://github.com/lincolnloop/python-qrcode

## 📄 License

This project is provided as-is for educational purposes.

## 🙏 Acknowledgments

Built as an alternative to complex university attendance systems, focusing on simplicity and ease of use.

---

**Made with ❤️ using Flask**
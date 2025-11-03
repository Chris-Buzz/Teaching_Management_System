# Teaching Management System - Deployment Guide

## Deploying to Vercel

This guide will help you deploy the Teaching Management System to Vercel for production use.

### Prerequisites

1. A [Vercel account](https://vercel.com/signup) (free tier works)
2. [Vercel CLI](https://vercel.com/cli) installed (optional, but recommended)
3. Git repository set up at: https://github.com/Chris-Buzz/Teaching_Management_System.git

### Quick Deployment Steps

#### Option 1: Deploy via Vercel Dashboard (Recommended)

1. **Push your code to GitHub:**
   ```bash
   git add .
   git commit -m "Prepare for Vercel deployment"
   git push origin main
   ```

2. **Import to Vercel:**
   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click "Add New Project"
   - Import your GitHub repository: `Chris-Buzz/Teaching_Management_System`
   - Vercel will automatically detect the Python Flask application

3. **Configure Environment Variables:**
   In the Vercel project settings, add these environment variables:
   - `SECRET_KEY`: A secure random string (generate with: `python -c "import secrets; print(secrets.token_hex(32))"`)
   - `VERCEL_ENV`: Set to `production`
   - `DATABASE_URL`: (Optional) PostgreSQL connection string for production database

4. **Deploy:**
   - Click "Deploy"
   - Vercel will build and deploy your application
   - You'll get a live URL (e.g., `your-app.vercel.app`)

#### Option 2: Deploy via Vercel CLI

1. **Install Vercel CLI:**
   ```bash
   npm install -g vercel
   ```

2. **Login to Vercel:**
   ```bash
   vercel login
   ```

3. **Deploy:**
   ```bash
   cd "i:\Projects\Teaching Management System"
   vercel
   ```

4. **Follow the prompts:**
   - Link to existing project or create new
   - Set environment variables when prompted
   - Deploy to production: `vercel --prod`

### Important Notes

#### Database Considerations

**⚠️ IMPORTANT:** SQLite (current database) has limitations on Vercel:
- Files are stored in `/tmp` which is ephemeral
- Data will be lost between deployments and server restarts

**Recommended Production Database Options:**

1. **PostgreSQL (Recommended):**
   - Use [Vercel Postgres](https://vercel.com/docs/storage/vercel-postgres)
   - Or use [Supabase](https://supabase.com/) (free tier available)
   - Or use [Neon](https://neon.tech/) (free tier available)

2. **Update for PostgreSQL:**
   ```bash
   pip install psycopg2-binary
   ```

   Add to `requirements.txt`:
   ```
   psycopg2-binary==2.9.9
   ```

   Set `DATABASE_URL` environment variable to your PostgreSQL connection string

#### Environment Variables to Set in Vercel

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key for sessions | `your-secret-key-here` |
| `VERCEL_ENV` | Environment indicator | `production` |
| `DATABASE_URL` | Database connection string | `postgresql://user:pass@host/db` |

### Post-Deployment Steps

1. **Test the Application:**
   - Visit your Vercel URL
   - Create a test teacher account
   - Create a test student account
   - Test all features (class creation, attendance, QR codes)

2. **Set up Custom Domain (Optional):**
   - Go to Project Settings > Domains
   - Add your custom domain
   - Update DNS records as instructed

3. **Monitor Application:**
   - Check Vercel logs for any errors
   - Monitor performance in Vercel Analytics

### Upgrading to PostgreSQL (Recommended for Production)

1. **Create a PostgreSQL database:**
   - Use Vercel Postgres, Supabase, or Neon
   - Get the connection string

2. **Update requirements.txt:**
   ```
   Flask==3.0.0
   Flask-SQLAlchemy==3.1.1
   Flask-Login==0.6.3
   Werkzeug==3.0.1
   qrcode==7.4.2
   Pillow==10.1.0
   psycopg2-binary==2.9.9
   ```

3. **Set DATABASE_URL in Vercel:**
   ```
   postgresql://username:password@host:5432/database
   ```

4. **Redeploy:**
   The database tables will be created automatically on first run

### Troubleshooting

#### Common Issues:

1. **Module not found errors:**
   - Ensure all dependencies are in `requirements.txt`
   - Redeploy after updating requirements

2. **Database connection errors:**
   - Check `DATABASE_URL` environment variable
   - Ensure database is accessible from Vercel

3. **Static files not loading:**
   - Check that `static/` folder is committed to git
   - Verify paths in templates use `url_for('static', filename='...')`

4. **Secret key errors:**
   - Set `SECRET_KEY` environment variable in Vercel

### Security Best Practices

1. **Never commit sensitive data:**
   - Use environment variables for secrets
   - The `.gitignore` file already excludes `.env` files

2. **Use HTTPS:**
   - Vercel provides HTTPS by default
   - Never disable it

3. **Set strong SECRET_KEY:**
   - Use a cryptographically secure random string
   - Never use the default or a simple string

4. **Keep dependencies updated:**
   - Regularly update packages for security patches
   - Monitor Vercel's security advisories

### Continuous Deployment

Vercel automatically deploys when you push to your main branch:

```bash
git add .
git commit -m "Update feature"
git push origin main
```

Vercel will:
1. Detect the push
2. Build the application
3. Run tests (if configured)
4. Deploy to production
5. Notify you of deployment status

### Support

- **Vercel Documentation:** https://vercel.com/docs
- **Flask Documentation:** https://flask.palletsprojects.com/
- **GitHub Issues:** https://github.com/Chris-Buzz/Teaching_Management_System/issues

### Local Development

To run locally:

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Access at: http://localhost:5000

---

## Summary

Your Teaching Management System is now ready for production deployment on Vercel!

**Key Features:**
- ✅ Modern, professional UI
- ✅ QR code attendance system
- ✅ Student and teacher dashboards
- ✅ Attendance tracking with Late status
- ✅ Individual student history
- ✅ CSV export functionality
- ✅ No-login QR check-in for students
- ✅ Production-ready configuration

**Next Steps:**
1. Push to GitHub
2. Deploy to Vercel
3. Set environment variables
4. (Optional) Upgrade to PostgreSQL
5. Test thoroughly
6. Share with users!

Good luck with your deployment! 🚀

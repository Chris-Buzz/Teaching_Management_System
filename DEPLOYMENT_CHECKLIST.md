# Deployment Checklist

Use this checklist to ensure your Teaching Management System is properly deployed to Vercel.

## Pre-Deployment Checklist

- [ ] All code committed to GitHub
- [ ] `.gitignore` file in place (excludes `.env`, `*.db`, `__pycache__/`, etc.)
- [ ] `requirements.txt` is up to date
- [ ] `vercel.json` configuration file exists
- [ ] `runtime.txt` specifies Python version
- [ ] Tested application locally
- [ ] All features working as expected

## GitHub Setup

- [ ] Repository created at: https://github.com/Chris-Buzz/Teaching_Management_System
- [ ] All files pushed to main branch
  ```bash
  git add .
  git commit -m "Ready for production deployment"
  git push origin main
  ```

## Vercel Setup

- [ ] Vercel account created (free tier is fine)
- [ ] New project imported from GitHub
- [ ] Repository linked to Vercel

## Environment Variables (Required)

Set these in Vercel Project Settings > Environment Variables:

- [ ] `SECRET_KEY`
  - Generate: `python -c "import secrets; print(secrets.token_hex(32))"`
  - Example: `a1b2c3d4e5f6...` (64 characters)

- [ ] `VERCEL_ENV`
  - Value: `production`

- [ ] `DATABASE_URL` (Optional but recommended)
  - For SQLite (temporary): `sqlite:////tmp/attendance.db`
  - For PostgreSQL (recommended): `postgresql://user:pass@host:5432/db`

## Database Setup (For Production)

### Option 1: SQLite (Quick Start - Not Recommended)
- [ ] Will use `/tmp/attendance.db`
- [ ] ⚠️ Data will be lost on redeployment
- [ ] Only for testing

### Option 2: PostgreSQL (Recommended)
- [ ] Create PostgreSQL database:
  - [ ] Vercel Postgres, OR
  - [ ] Supabase (https://supabase.com), OR
  - [ ] Neon (https://neon.tech)
- [ ] Get connection string
- [ ] Add to `DATABASE_URL` environment variable
- [ ] Add `psycopg2-binary==2.9.9` to requirements.txt

## Deployment

- [ ] Click "Deploy" in Vercel dashboard
- [ ] Wait for build to complete
- [ ] Check deployment logs for errors
- [ ] Note your deployment URL (e.g., `your-app.vercel.app`)

## Post-Deployment Testing

- [ ] Visit deployment URL
- [ ] Test registration
  - [ ] Create teacher account
  - [ ] Create student account
- [ ] Test teacher features
  - [ ] Create a class
  - [ ] Add student to class
  - [ ] Start attendance session
  - [ ] View QR code
- [ ] Test student features
  - [ ] Scan QR code (or visit check-in URL)
  - [ ] Enter email for check-in
  - [ ] Verify success modal appears
  - [ ] Check attendance marked
- [ ] Test teacher session management
  - [ ] View active session
  - [ ] Close session
  - [ ] Edit attendance records
  - [ ] View student history
  - [ ] Export CSV
- [ ] Test mobile responsiveness
- [ ] Test on different browsers

## Optional: Custom Domain

- [ ] Purchase/have custom domain
- [ ] Add to Vercel Project Settings > Domains
- [ ] Update DNS records as instructed
- [ ] Wait for SSL certificate provisioning
- [ ] Test custom domain

## Monitoring

- [ ] Check Vercel deployment logs
- [ ] Monitor for errors in Vercel dashboard
- [ ] Set up error notifications (optional)
- [ ] Monitor database usage (if using paid tier)

## Documentation

- [ ] Update README.md with live URL
- [ ] Document any custom configurations
- [ ] Create admin credentials documentation
- [ ] Share deployment URL with users

## Security Review

- [ ] SECRET_KEY is strong and unique
- [ ] No sensitive data in repository
- [ ] HTTPS is enforced (Vercel does this automatically)
- [ ] Environment variables are not exposed
- [ ] Database credentials are secure

## Backup Plan

- [ ] Know how to export database
- [ ] Have rollback procedure documented
- [ ] Keep local development environment synced

## Troubleshooting Common Issues

### Build Fails
- Check Python version in `runtime.txt`
- Verify all dependencies in `requirements.txt`
- Check Vercel build logs for specific errors

### Database Connection Errors
- Verify `DATABASE_URL` format
- Check database server is accessible
- Ensure database user has proper permissions

### QR Codes Not Working
- Use full URL including `https://`
- Test URL manually in browser first
- Ensure session is active

### Static Files Not Loading
- Verify `static/` folder is in repository
- Check paths use `url_for('static', filename='...')`
- Clear browser cache

## Success Criteria

Your deployment is successful when:
- [ ] Application loads without errors
- [ ] Users can register and login
- [ ] Teachers can create classes
- [ ] Students can be added to classes
- [ ] Attendance sessions can be started
- [ ] QR codes are generated and scannable
- [ ] Students can check in (with or without login)
- [ ] Success modal displays after check-in
- [ ] Teachers can view and edit attendance
- [ ] Student history is accessible
- [ ] CSV export works
- [ ] All features tested on mobile
- [ ] Application performs well under load

## Maintenance Tasks

Regular maintenance (weekly/monthly):
- [ ] Check for dependency updates
- [ ] Review error logs
- [ ] Backup database
- [ ] Test critical features
- [ ] Monitor storage usage
- [ ] Review security advisories

---

## Quick Reference

**GitHub Repository:** https://github.com/Chris-Buzz/Teaching_Management_System
**Vercel Dashboard:** https://vercel.com/dashboard
**Documentation:** See DEPLOYMENT.md for detailed instructions

**Support:**
- Vercel Docs: https://vercel.com/docs
- Flask Docs: https://flask.palletsprojects.com/
- GitHub Issues: https://github.com/Chris-Buzz/Teaching_Management_System/issues

---

**Congratulations on your deployment! 🎉**

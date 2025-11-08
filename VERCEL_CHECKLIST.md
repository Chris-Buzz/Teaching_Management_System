# ✅ Vercel Deployment Checklist - RollCallQR

## Pre-Deployment Verification

- [ ] Code pushed to GitHub (`main` branch)
- [ ] All files committed (no uncommitted changes)
- [ ] Python syntax valid: `python -m py_compile app.py`
- [ ] `requirements.txt` has all dependencies
- [ ] `wsgi.py` exists and is correct
- [ ] `vercel.json` is configured

---

## Required Environment Variables (SET THESE FIRST!)

Before you click "Deploy" on Vercel, you MUST set these three variables:

### 1️⃣ FLASK_ENV
```
Name: FLASK_ENV
Value: production
```

### 2️⃣ SECRET_KEY
Generate locally:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
Copy the output (looks like: `a7f5e8c2b9d1f4e6a3b8c5d2e9f6a1b8c7d4e1f8a5b2c9d6e3f0a7b4c1d8e5`)

```
Name: SECRET_KEY
Value: <paste-your-generated-key-here>
```

### 3️⃣ DATABASE_URL
Go to **Supabase Dashboard**:
1. Project Settings → Database
2. Copy **Connection Pooling** URL (port 6543)
3. **IMPORTANT**: Use this format exactly:
   ```
   postgresql://postgres.<PROJECT-REF>:<YOUR-PASSWORD>@aws-0-<region>.pooler.supabase.com:6543/postgres
   ```

```
Name: DATABASE_URL
Value: <paste-your-supabase-pooling-url-here>
```

---

## Deployment Steps

### Step 1: Set Environment Variables in Vercel

1. Go to Vercel Dashboard: https://vercel.com/dashboard
2. Click on your project: `Teaching_Management_System`
3. Go to **Settings** → **Environment Variables**
4. Add all three variables above
5. Click **Save**

### Step 2: Deploy

**Automatic (Recommended):**
- Just push to GitHub
- Vercel automatically deploys

**Manual:**
```bash
npm install -g vercel
cd "path/to/Teaching Management System"
vercel --prod
```

### Step 3: Verify

Wait 2-3 minutes for deployment, then test:

```bash
# Check health
curl https://your-vercel-url.vercel.app/health

# Visit home page (replace your-vercel-url)
https://your-vercel-url.vercel.app/
```

Should see login page.

---

## Common Deployment Issues

### ❌ 500 Error on Home Page

**Cause:** Missing or incorrect environment variables

**Fix:**
1. Check Vercel dashboard → Settings → Environment Variables
2. Verify all 3 variables are set:
   - [ ] FLASK_ENV = production
   - [ ] SECRET_KEY = (not empty)
   - [ ] DATABASE_URL = (not empty)
3. Redeploy: `vercel --prod`

### ❌ Database Connection Error

**Cause:** DATABASE_URL is wrong

**Check:**
- [ ] Using **Connection Pooling** URL (port 6543)?
- [ ] Not using port 5432?
- [ ] URL includes your password?
- [ ] Supabase project is active?

**Fix:**
1. Go to Supabase → Settings → Database → Connection Pooling
2. Copy the URL
3. Update DATABASE_URL in Vercel
4. Redeploy

### ❌ 502 Bad Gateway

**Cause:** Build failed or timeout

**Fix:**
1. Check build logs: `vercel logs <url>`
2. Ensure all dependencies are in requirements.txt
3. Try: `vercel --prod --force`

### ❌ Static Files Not Loading (CSS/JS broken)

**Cause:** Static routes not configured

**Fix:**
- vercel.json is already fixed
- Static files are in `/static` folder
- Redeploy: `vercel --prod`

---

## ✅ Verification Checklist After Deployment

- [ ] Health check returns 200: `curl https://your-app.vercel.app/health`
- [ ] Home page loads (redirects to login)
- [ ] Login page displays correctly
- [ ] Can register new account
- [ ] Can log in with registered account
- [ ] Can create a class
- [ ] Can start a session and generate QR code
- [ ] Can view attendance records
- [ ] Can export CSV

---

## 📊 Testing Student QR Check-In

1. Log in as teacher
2. Create test class
3. Add students
4. Start attendance session
5. Copy QR check-in link (or scan QR code)
6. Open link in new browser window (incognito)
7. Should see check-in success page
8. View attendance - should show new record

---

## 🔧 Troubleshooting Commands

### View Live Logs
```bash
vercel logs <your-vercel-url> --follow
```

### Force Rebuild
```bash
vercel --prod --force
```

### Check Environment Variables
```bash
vercel env ls
```

### Redeploy Manually
```bash
vercel --prod
```

---

## 💾 Backup & Database

**Data is safe:**
- ✅ All data stored in Supabase PostgreSQL
- ✅ Supabase provides automatic daily backups
- ✅ Vercel stores no data (stateless)

**To backup manually:**
1. Supabase Dashboard → Database → Backups
2. Download backup file

---

## 🎉 You're Deployed!

Your app is now live and scalable on Vercel!

**URL:** https://your-teaching-system.vercel.app

**Next steps:**
1. Invite teachers and students
2. Start taking attendance
3. Monitor logs for errors
4. Set up uptime monitoring on `/health` endpoint

---

## 📞 Support

- **Vercel Issues**: Check `vercel logs`
- **Database Issues**: Check Supabase Dashboard
- **Code Issues**: Check GitHub repo
- **Local Testing**: Run `python app.py` locally with `.env` file

---

*Generated: November 8, 2025*
*Last Updated: November 8, 2025*

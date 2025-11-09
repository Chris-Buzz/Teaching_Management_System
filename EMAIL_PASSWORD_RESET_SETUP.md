# 🔐 Email & Password Reset - Production Setup

## Overview

RollCallQR now has a **production-grade password reset system** with:
- ✅ HTML email templates
- ✅ Secure token generation
- ✅ Time-limited reset links
- ✅ SMTP email sending
- ✅ Graceful fallback
- ✅ Logging and monitoring

---

## How It Works

### 1. User Requests Password Reset
1. User clicks "Forgot Password" on login page
2. Enters their email address
3. Server generates secure token (expires in 1 hour)
4. Beautiful HTML email is sent with reset button

### 2. User Clicks Reset Link
1. User receives email with reset button
2. Clicks button → taken to reset page
3. Link validates the token
4. User enters new password
5. Password is securely hashed and stored
6. Token is destroyed

---

## Email Service Setup

### Option 1: Gmail (Easiest for Testing)

**Setup Gmail App Password:**

1. Go to: https://myaccount.google.com/apppasswords
2. Select "Mail" and "Windows Computer"
3. Generate app password (16-character)
4. Copy the password

**Set Environment Variables:**

```bash
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=xxxx xxxx xxxx xxxx
MAIL_DEFAULT_SENDER=noreply@rollcallqr.com
```

**Test locally:**
```bash
python app.py
```

When you request password reset, check your Gmail console output (will print email to console in development mode).

### Option 2: SendGrid (Recommended for Production)

**Create SendGrid Account:**

1. Sign up at: https://sendgrid.com/
2. Verify sender email
3. Create API key
4. Go to Settings → API Keys → Create API Key

**Set Environment Variables:**

```bash
MAIL_SERVER=smtp.sendgrid.net
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=apikey
MAIL_PASSWORD=SG.your-api-key-here
MAIL_DEFAULT_SENDER=noreply@yourdomain.com
```

### Option 3: AWS SES (Scalable)

**Setup AWS SES:**

1. Go to AWS Console → SES
2. Verify your email domain
3. Get SMTP credentials from SES Console
4. Create IAM user with SES permissions

**Set Environment Variables:**

```bash
MAIL_SERVER=email-smtp.region.amazonaws.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-username
MAIL_PASSWORD=your-password
MAIL_DEFAULT_SENDER=noreply@yourdomain.com
```

---

## Deployment Configuration

### Vercel with SendGrid

1. **Install SendGrid CLI (optional):**
   ```bash
   npm install -g sendgrid-cli
   ```

2. **Add Environment Variables to Vercel:**
   - Go to Vercel Dashboard → Project Settings → Environment Variables
   - Add all 5 email variables (see above)

3. **Deploy:**
   ```bash
   git push origin main
   ```

4. **Test:**
   - Visit your Vercel URL
   - Go to Forgot Password
   - Enter your email
   - Check inbox for reset link (may take 30 seconds)

### Heroku with SendGrid

1. **Add SendGrid Add-on:**
   ```bash
   heroku addons:create sendgrid:starter
   ```

2. **Verify Environment Variables:**
   ```bash
   heroku config
   ```

3. **Set Missing Variables:**
   ```bash
   heroku config:set MAIL_DEFAULT_SENDER=noreply@yourdomain.com
   ```

### Traditional Server (AWS EC2, DigitalOcean, etc.)

```bash
# Set in .env file or system environment
export MAIL_SERVER=smtp.sendgrid.net
export MAIL_PORT=587
export MAIL_USE_TLS=True
export MAIL_USERNAME=apikey
export MAIL_PASSWORD=SG.your-key
export MAIL_DEFAULT_SENDER=noreply@domain.com

# Run app
gunicorn wsgi:app
```

---

## Code Architecture

### Password Reset Flow

```python
# 1. User requests reset
POST /forgot-password
→ Generate token with expiry
→ Send email (send_password_reset_email)
→ Redirect to login

# 2. User clicks email link
GET /reset-password/<token>
→ Verify token exists and isn't expired
→ Show reset form

# 3. User submits new password
POST /reset-password/<token>
→ Validate password strength
→ Hash and save password
→ Clear token
→ Redirect to login
```

### Email Template

HTML template includes:
- RollCallQR branding
- Clear call-to-action button
- Plain text fallback
- Professional styling
- Security disclaimer

---

## Testing Password Reset

### Local Development

```bash
# 1. Start app
python app.py

# 2. Go to login page
http://localhost:5000/login

# 3. Click "Forgot Password"

# 4. Enter email

# 5. Check console output (will print email in dev mode)
```

Output example:
```
✉️  EMAIL WOULD BE SENT TO: ['user@example.com']
   SUBJECT: RollCallQR - Password Reset Request
```

### Production Testing

1. **Register with real email:**
   ```
   Name: Test User
   Email: your-real-email@gmail.com
   Password: TestPass123!
   Role: Teacher
   ```

2. **Log out and forgot password:**
   - Go to Forgot Password
   - Enter your email
   - Wait 30 seconds

3. **Check email:**
   - Check inbox and spam folder
   - Click "Reset Password" button
   - Enter new password
   - Success!

---

## Troubleshooting

### Email Not Sending

**Symptoms:** Password reset requested but no email received

**Checklist:**
- [ ] MAIL_SERVER set in environment variables
- [ ] MAIL_USERNAME set (or "apikey" for SendGrid)
- [ ] MAIL_PASSWORD set correctly
- [ ] MAIL_DEFAULT_SENDER set
- [ ] Email service account is active
- [ ] Not in development mode (emails print to console)

**Debug:**
```python
# Add to app.py temporarily
@app.route('/test-email')
def test_email():
    from flask_mail import Message
    msg = Message('Test', recipients=['your-email@example.com'], body='Test body')
    mail.send(msg)
    return 'Email sent!'
```

### Token Expired Error

**Symptom:** "Invalid or expired reset link"

**Cause:** Token expires after 1 hour

**Solution:** Request new password reset

### SMTP Connection Error

**Symptom:** "SMTP connection refused" or "timeout"

**Causes:**
- Wrong SMTP server
- Wrong port (587 for TLS, 465 for SSL)
- Firewall blocking SMTP
- Email service down

**Fix:**
```bash
# Verify SMTP works locally
telnet smtp.gmail.com 587

# Check credentials in environment
echo $MAIL_USERNAME
echo $MAIL_PASSWORD
```

---

## Email Templates

### HTML Email Example

The HTML email includes:
- RollCallQR header with branding
- Clear greeting
- Explanation of purpose
- Large reset button
- Security disclaimer
- Professional footer

**Customization:**

Edit `send_password_reset_email()` function in `app.py`:

```python
def send_password_reset_email(user_email, reset_url):
    msg = Message(
        subject='Custom Subject',  # ← Change here
        recipients=[user_email],
        html=f"""
        <html>
            <body>
                <!-- Customize HTML here -->
                <h1>Your Company Name</h1>
                ...
            </body>
        </html>
        """
    )
    mail.send(msg)
```

---

## Security Features

| Feature | Implementation |
|---------|-----------------|
| **Token Generation** | `secrets.token_urlsafe(32)` - cryptographically secure |
| **Token Storage** | Stored in database (not sent in URL fragment) |
| **Token Expiry** | 1 hour (configurable) |
| **Password Hashing** | Werkzeug with salt - never stored plain text |
| **Email Validation** | Regex pattern matching RFC 5322 |
| **Rate Limiting** | 3 requests per hour per IP |
| **CSRF Protection** | Flask-WTF tokens on all forms |
| **Logging** | All resets logged for audit trail |

---

## Monitoring & Logging

### View Password Reset Activity

```python
# In logs or database query:
app.logger.info(f'Password reset email sent to {user.email}')
app.logger.info(f'Password reset attempt for {user.email}')
app.logger.warning(f'Failed to send password reset email to {user.email}')
```

### Monitor Email Delivery

**Gmail:**
- Check account activity: https://myaccount.google.com/security

**SendGrid:**
- Go to Dashboard → Email Activity
- View delivery status and bounces

**AWS SES:**
- Go to SES Console → Statistics
- View bounce and complaint rates

---

## Rate Limiting

Password reset endpoint has rate limiting:

```
3 requests per hour per IP address
```

This prevents:
- Brute force attacks
- Email spam
- Account enumeration

---

## Next Steps

1. ✅ Choose email service (Gmail for testing, SendGrid for production)
2. ✅ Set environment variables
3. ✅ Test locally with `python app.py`
4. ✅ Deploy to Vercel/Heroku
5. ✅ Test with real email
6. ✅ Monitor email delivery
7. ✅ Update support docs with password reset instructions

---

## Production Checklist

- [ ] Email service account created and verified
- [ ] MAIL_SERVER configured
- [ ] MAIL_USERNAME and MAIL_PASSWORD set
- [ ] MAIL_DEFAULT_SENDER domain verified
- [ ] Tested locally with dev email account
- [ ] Tested in production with real account
- [ ] Email arrives within 30 seconds
- [ ] Reset link works correctly
- [ ] Token expires after 1 hour
- [ ] Rate limiting working (3/hour limit)
- [ ] Monitoring set up for failed emails
- [ ] Support docs mention password reset feature

---

## References

- **Flask-Mail Docs**: https://pythonhosted.org/Flask-Mail/
- **SendGrid SMTP**: https://docs.sendgrid.com/ui/account-and-settings/smtp
- **Gmail App Passwords**: https://support.google.com/accounts/answer/185833
- **AWS SES Setup**: https://docs.aws.amazon.com/ses/latest/dg/

---

*Generated: November 9, 2025*  
*Version: 1.0.0*  
*Status: Production Ready*


# 💻 JavaScript Architecture & Development Guide

## Overview

RollCallQR now has **separated, production-grade JavaScript code** in `/static/js/app.js` with:

- ✅ Modular architecture
- ✅ No inline scripts (clean templates)
- ✅ Utility functions library
- ✅ Client timestamp handling
- ✅ Form validation
- ✅ Toast notifications
- ✅ API helpers
- ✅ Proper error handling

---

## File Structure

```
static/
├── css/
│   └── style.css (1348 lines - all styling)
└── js/
    └── app.js (250+ lines - all JavaScript)

templates/
├── base.html (references app.js with <script> tag)
├── view_class.html (uses functions from app.js)
├── check_in.html (uses functions from app.js)
└── ... (other templates)
```

---

## JavaScript Architecture

### Module Pattern

The `app.js` file uses the **Module Pattern** for:
- Encapsulation
- Namespace avoidance
- Public/private separation

```javascript
// Public functions (accessed globally)
function showToast(message, type) { ... }
function showTab(tabName) { ... }

// Private utilities (internal only)
function validatePasswordStrength(password) { ... }

// Export for modules (if using ES6)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ... };
}
```

---

## Core Utilities

### 1. Toast Notifications

**Usage:**
```javascript
showToast('Success!', 'success', 3000);
showToast('Error occurred', 'danger');
showToast('Warning message', 'warning');
showToast('Info message', 'info');
```

**Types:**
- `success` - Green, checkmark icon
- `danger` - Red, X icon
- `error` - Alias for `danger`
- `warning` - Orange, triangle icon
- `info` - Blue, info icon (default)

**Features:**
- Auto-dismisses after 4 seconds (customizable)
- Smooth slide-in animation
- Manual close button
- Stacks multiple toasts

### 2. Tab Switching

**Usage:**
```javascript
// In HTML:
<button class="tab-btn" onclick="showTab('students')">Students</button>
<div class="tab-pane" id="students">...</div>

// JavaScript handles visibility
showTab('students');
```

### 3. CSV Template Download

**Usage:**
```javascript
// In HTML:
<a href="#" onclick="showCsvTemplate(event); return false;">Download Template</a>

// Generates and downloads CSV file
```

**Template:**
```csv
Email,Name,Student ID
student1@example.com,John Doe,STU001
student2@example.com,Jane Smith,STU002
```

### 4. Client Timestamp Capture

**Purpose:**
Captures timezone-aware timestamps on client before sending to server.

**Usage:**
```javascript
// Automatically added to forms on submit:
<form id="checkInForm" method="POST" onsubmit="addClientTimestampToForm('checkInForm')">
    <!-- Hidden input added automatically -->
    <!-- <input type="hidden" name="client_timestamp" value="2025-11-09T...Z"> -->
</form>

// Or manually:
const timestamp = getCurrentTimestamp(); // Returns ISO 8601 UTC
```

**Format:**
```
2025-11-09T15:30:45.123Z (ISO 8601 UTC)
```

Server converts to Eastern timezone before storing.

### 5. Form Validation

**Email Validation:**
```javascript
validateEmail('user@example.com'); // true
validateEmail('invalid.email'); // false
```

**Password Strength Check:**
```javascript
const result = validatePasswordStrength('MyPass123!');
// Returns:
// {
//   isValid: true,
//   requirements: {
//     uppercase: true,
//     lowercase: true,
//     number: true,
//     length: true
//   }
// }
```

**Requirements:**
- At least 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number

### 6. API Calls

**Usage:**
```javascript
// GET request
const data = await apiCall('/api/endpoint');

// POST request
const response = await apiCall('/api/endpoint', 'POST', { key: 'value' });

// Error handling automatic
// Returns null on error + shows toast
```

### 7. Utility Functions

**Copy to Clipboard:**
```javascript
copyToClipboard('text to copy');
// Shows "Copied to clipboard!" toast
```

**Smooth Scroll:**
```javascript
smoothScroll('elementId');
// Smooth scroll to element with id
```

**Toggle Element:**
```javascript
toggleElement('elementId');
// Shows/hides element with animation
```

**Debounce (for performance):**
```javascript
const search = debounce(function(query) {
    // Expensive operation
}, 500);

input.addEventListener('input', (e) => search(e.target.value));
// Only called 500ms after user stops typing
```

**Format Date:**
```javascript
formatDate('2025-11-09T15:30:00Z');
// Returns: "Nov 9, 2025, 3:30 PM"
```

**Delete Confirmation:**
```javascript
if (confirmDelete('Delete this class?')) {
    // User confirmed
    form.submit();
}
```

---

## Integration Examples

### Example 1: Class Management Page

```html
<!-- view_class.html -->

<!-- Switch between tabs -->
<button onclick="showTab('students')">Students</button>
<button onclick="showTab('sessions')">Sessions</button>

<div id="students" class="tab-pane">
    <!-- Student list -->
</div>

<div id="sessions" class="tab-pane" style="display:none;">
    <!-- Sessions list -->
</div>

<!-- Delete class with confirmation -->
<form method="POST" action="/delete" onsubmit="return confirmDelete('Delete this class?')">
    <!-- form fields -->
</form>

<!-- CSV upload template -->
<a href="#" onclick="showCsvTemplate(event); return false;">
    Download Student Template
</a>
```

### Example 2: Check-In Page

```html
<!-- check_in.html -->

<form id="checkInForm" method="POST" onsubmit="addClientTimestampToForm('checkInForm')">
    <input type="email" name="email" required>
    <!-- Timestamp automatically added before submit -->
    <button type="submit">Check In</button>
</form>

<script>
    // Success handling
    if (checkInSuccess) {
        showToast('✓ Attendance marked!', 'success');
        // Redirect after 2 seconds
        setTimeout(() => location.href = '/dashboard', 2000);
    }
</script>
```

### Example 3: Password Reset

```html
<!-- forgot_password.html -->

<form method="POST" id="resetForm">
    <input type="email" name="email" 
           onchange="validateEmail(this.value) || showToast('Invalid email', 'danger')"
           required>
    <button type="submit">Send Reset Link</button>
</form>

<!-- reset_password.html -->

<form method="POST" id="newPasswordForm">
    <input type="password" name="password" id="password"
           onchange="validatePasswordStrength(this.value).isValid || 
                    showToast('Password too weak', 'danger')"
           required>
    <button type="submit">Reset Password</button>
</form>
```

---

## Best Practices

### ✅ DO

```javascript
// ✅ Use exported utility functions
showToast('Message', 'success');

// ✅ Validate before form submit
if (!validateEmail(email)) return;

// ✅ Use debounce for frequent events
const search = debounce(handleSearch, 300);
input.addEventListener('input', search);

// ✅ Handle errors in async calls
const result = await apiCall('/endpoint');
if (!result) { /* handle error */ }

// ✅ Use client timestamps
addClientTimestampToForm('formId');
```

### ❌ DON'T

```javascript
// ❌ Inline JavaScript in HTML
<button onclick="var x = 5; ..." > <!-- WRONG -->

// ❌ Global variables
var globalCount = 0; // BAD

// ❌ Hardcoded values
fetch('/api/users'); // Should parameterize

// ❌ No error handling
async function fetch(url) { ... } // What if it fails?

// ❌ Synchronous/blocking operations
const result = synchronousFetch('/api/data'); // Freezes UI
```

---

## Performance Tips

### 1. Lazy Load Scripts

```html
<!-- Already in base.html -->
<script src="{{ url_for('static', filename='js/app.js') }}" defer></script>

<!-- 'defer' means:
    - Script loads in background
    - Doesn't block HTML parsing
    - Executes after DOM is ready
-->
```

### 2. Minimize DOM Queries

```javascript
// ❌ BAD - Queries DOM 3 times
document.getElementById('form').style.display = 'none';
document.getElementById('form').classList.add('error');
document.getElementById('form').focus();

// ✅ GOOD - Query once, reuse
const form = document.getElementById('form');
form.style.display = 'none';
form.classList.add('error');
form.focus();
```

### 3. Use Event Delegation

```javascript
// ❌ BAD - Attaches listener to every button
document.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', deleteItem);
});

// ✅ GOOD - One listener on parent
document.addEventListener('click', e => {
    if (e.target.classList.contains('delete-btn')) {
        deleteItem(e);
    }
});
```

### 4. Debounce/Throttle

```javascript
// ✅ Prevents excessive function calls
const debouncedSearch = debounce(search, 300);
input.addEventListener('input', debouncedSearch);

// Called 300ms after user stops typing, not on every keystroke
```

---

## Development Workflow

### Adding New Functionality

1. **Add function to `app.js`:**
   ```javascript
   function myNewFeature() {
       // implementation
   }
   ```

2. **Export if needed for modules:**
   ```javascript
   if (typeof module !== 'undefined' && module.exports) {
       module.exports = {
           ...existing exports,
           myNewFeature
       };
   }
   ```

3. **Use in template:**
   ```html
   <button onclick="myNewFeature()">Click Me</button>
   ```

### Debugging

```javascript
// Browser Console (F12):

// Check if function exists
typeof showToast // 'function'

// Call function with test data
showToast('Test message', 'success');

// Check errors
console.error('Debug message');

// Monitor performance
console.time('operationName');
// ... code ...
console.timeEnd('operationName');
```

---

## Browser Support

- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+

Features used:
- ES6 const/let
- Arrow functions (in debounce)
- Template literals (in toasts)
- Async/await (in apiCall)

---

## Accessibility

JavaScript maintains accessibility:

- ✅ Forms work without JavaScript (progressive enhancement)
- ✅ Keyboard navigation supported
- ✅ Toast notifications use color + icon + text
- ✅ ARIA labels preserved in HTML
- ✅ Focus management in modals

---

## Security Considerations

| Issue | Mitigation |
|-------|-----------|
| **XSS (Cross-Site Scripting)** | Input sanitized, output escaped by Flask/Jinja2 |
| **CSRF** | Flask-WTF tokens on all forms, verified server-side |
| **Passwords** | Never transmitted in plain text, hashed with salt |
| **Tokens** | Secure token generation with `secrets.token_urlsafe()` |
| **API Calls** | CSRF tokens included, server validates |

---

## Troubleshooting

### Function Not Found

```javascript
// Error: showToast is not defined

// Solution: Make sure script is loaded
// Check: <script src="/static/js/app.js" defer></script>
// Wait for DOMContentLoaded if called early
```

### Toast Not Appearing

```javascript
// Problem: Toast doesn't show

// Check: Container exists in HTML
<div id="toastContainer"></div>

// Check: CSS is loaded
<link rel="stylesheet" href="/static/css/style.css">
```

### Form Not Submitting With Timestamp

```javascript
// Problem: Timestamp not added

// Solution: Make sure form has id
<form id="myForm" ...>

// And call before submit
addClientTimestampToForm('myForm');
```

---

## Testing

### Unit Tests (Optional)

```javascript
// tests/app.test.js
describe('validateEmail', () => {
    it('should validate valid emails', () => {
        expect(validateEmail('user@example.com')).toBe(true);
    });
    
    it('should reject invalid emails', () => {
        expect(validateEmail('invalid')).toBe(false);
    });
});
```

### Manual Testing Checklist

- [ ] Toasts appear and dismiss correctly
- [ ] Form validation works
- [ ] CSV template downloads
- [ ] Tab switching works
- [ ] Timestamps are captured
- [ ] Delete confirmations work
- [ ] Copy to clipboard works
- [ ] All buttons functional

---

## Migration Guide (From Inline to External)

If you have inline scripts, migrate to `app.js`:

```html
<!-- BEFORE: Inline script -->
<script>
function myFunc() { ... }
</script>

<!-- AFTER: External script -->
<!-- In app.js -->
function myFunc() { ... }

<!-- In template -->
<!-- Script loaded from base.html -->
```

---

## Future Enhancements

- [ ] Add TypeScript support
- [ ] Add unit tests with Jest
- [ ] Add bundle optimization (minification)
- [ ] Add service worker for offline support
- [ ] Add real-time updates with WebSockets
- [ ] Add analytics tracking
- [ ] Add error reporting (Sentry)

---

## References

- MDN JavaScript: https://developer.mozilla.org/en-US/docs/Web/JavaScript/
- JavaScript Best Practices: https://javascript.info/
- Fetch API: https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API
- Web Storage: https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API

---

*Generated: November 9, 2025*  
*Version: 1.0.0*  
*Status: Production Ready*


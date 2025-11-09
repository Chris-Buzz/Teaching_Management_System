/**
 * RollCallQR - Main JavaScript Module
 * Production-grade utilities for attendance tracking
 */

// Toast notification system
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    
    toast.className = 'toast';
    let icon = 'fa-info-circle';
    let bgColor = 'rgba(59, 130, 246, 0.95)';
    let borderColor = '#3b82f6';
    
    if (type === 'success') {
        icon = 'fa-check-circle';
        bgColor = 'rgba(34, 197, 94, 0.95)';
        borderColor = '#22c55e';
    } else if (type === 'danger' || type === 'error') {
        icon = 'fa-exclamation-circle';
        bgColor = 'rgba(239, 68, 68, 0.95)';
        borderColor = '#ef4444';
    } else if (type === 'warning') {
        icon = 'fa-exclamation-triangle';
        bgColor = 'rgba(245, 158, 11, 0.95)';
        borderColor = '#f59e0b';
    }
    
    toast.innerHTML = `
        <div style="background: ${bgColor}; border-left: 4px solid ${borderColor}; padding: 1rem; border-radius: 8px; display: flex; align-items: center; gap: 1rem; color: white; min-width: 300px;">
            <i class="fas ${icon}" style="font-size: 1.25rem; flex-shrink: 0;"></i>
            <span>${message}</span>
            <button style="background: none; border: none; color: white; cursor: pointer; font-size: 1.25rem; margin-left: auto;" onclick="this.closest('.toast').remove();">&times;</button>
        </div>
    `;
    
    container.appendChild(toast);
    
    const slideInAnimation = toast.animate([
        { transform: 'translateX(400px)', opacity: 0 },
        { transform: 'translateX(0)', opacity: 1 }
    ], { duration: 300, easing: 'cubic-bezier(0.34, 1.56, 0.64, 1)' });
    
    setTimeout(() => {
        toast.animate([
            { transform: 'translateX(0)', opacity: 1 },
            { transform: 'translateX(400px)', opacity: 0 }
        ], { duration: 300, easing: 'ease-in' });
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// Tab switching for class view
function showTab(tabName) {
    const tabs = document.querySelectorAll('.tab-pane');
    tabs.forEach(tab => {
        tab.style.display = tab.id === tabName ? 'block' : 'none';
    });
    
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('onclick').includes(tabName));
    });
}

// CSV template download
function showCsvTemplate(e) {
    e.preventDefault();
    const csv = "Email,Name,Student ID\nstudent1@example.com,John Doe,STU001\nstudent2@example.com,Jane Smith,STU002\n";
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'student_template.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}

// Get current time in ISO format (UTC)
function getCurrentTimestamp() {
    return new Date().toISOString();
}

// Capture client timestamp for forms
function addClientTimestampToForm(formId) {
    const form = document.getElementById(formId);
    if (form) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'client_timestamp';
        input.value = getCurrentTimestamp();
        form.appendChild(input);
    }
}

// Confirm deletion dialog
function confirmDelete(message = 'Are you sure? This action cannot be undone.') {
    return confirm(message);
}

// Format date to readable format
function formatDate(isoString) {
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Toggle visibility with smooth animation
function toggleElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.style.display = element.style.display === 'none' ? 'block' : 'none';
    }
}

// Form validation
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

function validatePasswordStrength(password) {
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasMinLength = password.length >= 8;
    
    return {
        isValid: hasUpperCase && hasLowerCase && hasNumber && hasMinLength,
        requirements: {
            uppercase: hasUpperCase,
            lowercase: hasLowerCase,
            number: hasNumber,
            length: hasMinLength
        }
    };
}

// Initialize forms with client timestamp
document.addEventListener('DOMContentLoaded', function() {
    // Add timestamp to all forms that need it
    const startSessionForm = document.getElementById('startSessionForm');
    if (startSessionForm) {
        startSessionForm.addEventListener('submit', function() {
            addClientTimestampToForm('startSessionForm');
        });
    }
    
    const closeSessionForm = document.getElementById('closeSessionForm');
    if (closeSessionForm) {
        closeSessionForm.addEventListener('submit', function() {
            addClientTimestampToForm('closeSessionForm');
        });
    }
    
    const checkInForm = document.getElementById('checkInForm');
    if (checkInForm) {
        checkInForm.addEventListener('submit', function() {
            addClientTimestampToForm('checkInForm');
        });
    }
});

// Debounce function for API calls
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// API call helper with error handling
async function apiCall(url, method = 'GET', data = null) {
    try {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
            }
        };
        
        if (data) {
            options.body = JSON.stringify(data);
        }
        
        const response = await fetch(url, options);
        
        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        showToast(`Error: ${error.message}`, 'danger');
        return null;
    }
}

// Copy to clipboard utility
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success', 2000);
    }).catch(() => {
        showToast('Failed to copy', 'danger');
    });
}

// Smooth scroll to element
function smoothScroll(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// Export for use in modules (if using ES6)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        showToast,
        showTab,
        showCsvTemplate,
        getCurrentTimestamp,
        addClientTimestampToForm,
        confirmDelete,
        formatDate,
        toggleElement,
        validateEmail,
        validatePasswordStrength,
        debounce,
        apiCall,
        copyToClipboard,
        smoothScroll
    };
}

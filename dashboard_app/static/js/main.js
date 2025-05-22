// Theme toggling
function toggleTheme() {
    const body = document.body;
    const currentTheme = body.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    body.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

// Set theme on page load
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.body.setAttribute('data-theme', savedTheme);
});

// Password strength checker
function checkPasswordStrength(password) {
    const requirements = {
        length: password.length >= 12,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[!@#$%^&*()]/.test(password)
    };
    
    return {
        valid: Object.values(requirements).every(Boolean),
        requirements
    };
}

// Auto-logout after inactivity
let inactivityTimeout;
const TIMEOUT_MINUTES = 30;

function resetInactivityTimer() {
    clearTimeout(inactivityTimeout);
    inactivityTimeout = setTimeout(() => {
        window.location.href = '/logout';
    }, TIMEOUT_MINUTES * 60 * 1000);
}

document.addEventListener('mousemove', resetInactivityTimer);
document.addEventListener('keypress', resetInactivityTimer);

// CSRF token setup for AJAX requests
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

// Add CSRF token to all AJAX requests
document.addEventListener('DOMContentLoaded', () => {
    const token = getCsrfToken();
    if (token) {
        axios.defaults.headers.common['X-CSRF-TOKEN'] = token;
    }
}); 

document.addEventListener('DOMContentLoaded', () => {
  // Login form handling
  const loginForm = document.getElementById('loginForm');
  const alertBox = document.getElementById('alertBox');
  const emailInput = document.getElementById('emailInput');
  const passwordInput = document.getElementById('passwordInput');
  const emailError = document.getElementById('emailError');
  const passwordError = document.getElementById('passwordError');
  const submitBtn = document.getElementById('submitBtn');
  const redirectInput = document.getElementById('redirectInput');

  function showAlert(message, type = 'error') {
    if (!alertBox) return;
    alertBox.textContent = message;
    alertBox.className = `alert-box alert-${type}`;
    alertBox.classList.remove('hidden');
  }

  function hideAlert() {
    if (!alertBox) return;
    alertBox.textContent = '';
    alertBox.className = 'alert-box hidden';
  }

  function clearFieldErrors() {
    if (emailError) emailError.textContent = '';
    if (passwordError) passwordError.textContent = '';
    if (emailInput) emailInput.classList.remove('input-error');
    if (passwordInput) passwordInput.classList.remove('input-error');
  }

  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearFieldErrors();
      hideAlert();

      const email = emailInput ? emailInput.value.trim() : '';
      const password = passwordInput ? passwordInput.value : '';
      let hasError = false;

      // Client-side field validation
      if (!email) {
        if (emailError) emailError.textContent = 'Email address is required.';
        if (emailInput) emailInput.classList.add('input-error');
        hasError = true;
      } else if (!email.includes('@') || !email.includes('.')) {
        if (emailError) emailError.textContent = 'Please enter a valid email address.';
        if (emailInput) emailInput.classList.add('input-error');
        hasError = true;
      }

      if (!password) {
        if (passwordError) passwordError.textContent = 'Password is required.';
        if (passwordInput) passwordInput.classList.add('input-error');
        hasError = true;
      }

      if (hasError) {
        showAlert('Please resolve the errors highlighted below.');
        return;
      }

      // Disable button while processing
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Authenticating...';
      }

      try {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            email,
            password,
            redirect: redirectInput ? redirectInput.value : '/dashboard'
          })
        });

        const data = await response.json();

        if (response.ok && data.success) {
          showAlert('Authentication successful! Redirecting...', 'success');
          window.location.href = data.redirectTo || '/dashboard';
        } else {
          showAlert(data.error || 'Authentication failed. Please check credentials.');
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Sign In';
          }
        }
      } catch (err) {
        showAlert('Network error or server unreachable. Please try again.');
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Sign In';
        }
      }
    });
  }

  // Logout button handling
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      logoutBtn.disabled = true;
      logoutBtn.textContent = 'Logging out...';
      try {
        const response = await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });
        if (response.ok) {
          window.location.href = '/login';
        } else {
          window.location.href = '/login';
        }
      } catch (e) {
        window.location.href = '/login';
      }
    });
  }

  // Profile API verification button on dashboard
  const refreshProfileBtn = document.getElementById('refreshProfileBtn');
  const profileApiOutput = document.getElementById('profileApiOutput');
  if (refreshProfileBtn && profileApiOutput) {
    refreshProfileBtn.addEventListener('click', async () => {
      try {
        const response = await fetch('/api/profile');
        const data = await response.json();
        profileApiOutput.textContent = JSON.stringify(data, null, 2);
        profileApiOutput.classList.remove('hidden');
      } catch (err) {
        profileApiOutput.textContent = 'Error fetching profile: ' + err.message;
        profileApiOutput.classList.remove('hidden');
      }
    });
  }
});

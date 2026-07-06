// Fix: Prevent autocomplete on password fields to avoid clipboard exposure
function disablePasswordAutocomplete() {
  document.querySelectorAll('input[type="password"]').forEach(input => {
    input.setAttribute('autocomplete', 'off');
    // Alternatively, use 'new-password' for modern browsers
    // input.setAttribute('autocomplete', 'new-password');
  });
}

// Execute on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', disablePasswordAutocomplete);
} else {
  disablePasswordAutocomplete();
}
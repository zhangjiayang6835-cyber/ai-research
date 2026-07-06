// Fix: Prevent password autocomplete and clipboard leakage
document.addEventListener('DOMContentLoaded', function() {
  var passwordInputs = document.querySelectorAll('input[type="password"]');
  passwordInputs.forEach(function(input) {
    input.setAttribute('autocomplete', 'new-password');
  });
});
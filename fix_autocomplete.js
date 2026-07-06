document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('input[type="password"]').forEach(function(input) {
    input.setAttribute('autocomplete', 'new-password');
  });
});
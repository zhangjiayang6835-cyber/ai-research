// Fix autocomplete on password fields
(function() {
  'use strict';
  function fixPasswordAutocomplete() {
    var passwordFields = document.querySelectorAll('input[type="password"]');
    for (var i = 0; i < passwordFields.length; i++) {
      passwordFields[i].setAttribute('autocomplete', 'new-password');
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', fixPasswordAutocomplete);
  } else {
    fixPasswordAutocomplete();
  }
})();
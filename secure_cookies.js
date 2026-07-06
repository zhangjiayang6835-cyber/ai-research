// Example of setting secure cookies to mitigate cookie theft in case of subdomain takeover
// Use HttpOnly, Secure, SameSite attributes

function setSecureCookie(name, value, days) {
    let expires = '';
    if (days) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = '; expires=' + date.toUTCString();
    }
    // Ensure cookie is not accessible via JavaScript (HttpOnly)
    // Only sent over HTTPS (Secure)
    // SameSite=Strict prevents CSRF and limits cookie sending in cross-site requests
    document.cookie = name + '=' + (value || '') + expires + '; path=/; Secure; HttpOnly; SameSite=Strict';
}

// Usage example:
// setSecureCookie('session_token', 'abc123', 7);

// Additionally, ensure authentication cookies are scoped to the specific path and domain
// Do not use wildcard domains; use the specific subdomain if needed.
// For subdomain takeover protection, also consider using __Host- prefix for cookies:
// The __Host- prefix requires that the cookie has Secure flag, path=/, and no Domain attribute.
// Example:
// document.cookie = '__Host-session=abc123; path=/; Secure; HttpOnly; SameSite=Strict';

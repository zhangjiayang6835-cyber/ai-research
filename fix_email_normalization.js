/**
 * Normalize email to prevent account takeover via email normalization attacks
 * For Gmail: remove dots before @gmail.com, remove + and everything after it
 * For all providers: lowercase the entire email
 */
function normalizeEmail(email) {
    if (!email || !email.includes('@')) {
        throw new Error('Invalid email address');
    }
    
    email = email.trim().toLowerCase();
    const [local, domain] = email.split('@', 2);
    
    // Define known Google domains for dot and plus handling
    const googleDomains = ['gmail.com', 'googlemail.com'];
    
    if (googleDomains.includes(domain)) {
        // Remove dots from the local part
        let normalizedLocal = local.replace(/\./g, '');
        // Remove + and everything after it
        const plusIndex = normalizedLocal.indexOf('+');
        if (plusIndex !== -1) {
            normalizedLocal = normalizedLocal.substring(0, plusIndex);
        }
        return `${normalizedLocal}@${domain}`;
    }
    
    // For other domains, simply lowercasing is usually sufficient
    // You may add specific rules for other providers as needed
    return `${local}@${domain}`;
}

// Example usage:
// normalizeEmail("Test.User+spam@GMAIL.COM") returns "testuser@gmail.com"

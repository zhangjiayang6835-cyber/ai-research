import re

def fix_password_autocomplete(html_content):
    # Add autocomplete="new-password" to password inputs without it
    pattern = r'(<input\s[^>]*?type=["\']password["\'][^>]*?(?!autocomplete)[^>]*?/?>)'
    def add_autocomplete(match):
        tag = match.group(1)
        if 'autocomplete' not in tag.lower():
            tag = tag.rstrip('/>') + ' autocomplete="new-password" />'
        return tag
    return re.sub(pattern, add_autocomplete, html_content, flags=re.IGNORECASE)
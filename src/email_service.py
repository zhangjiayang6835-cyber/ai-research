"""
Secure email template rendering service.
Prevents SSTI by ensuring user input is always passed as Jinja2 context variables,
never concatenated into template strings.

Fixes: Issue #1184 — SSTI in Email Template Engine → Sandbox Escape ($200)
"""

from markupsafe import escape
from flask import render_template_string


# ---------------------------------------------------------------------------
# Pre-defined templates (never constructed from user input)
# ---------------------------------------------------------------------------

RESET_EMAIL_TEMPLATE = """\
<h1>Password Reset</h1>
<p>Click the link below to reset your password:</p>
<a href="http://example.com/reset?token={{ token }}&email={{ email }}">Reset</a>
"""

WELCOME_EMAIL_TEMPLATE = """\
Welcome, {{ name }}! Thanks for joining.
"""

NOTIFICATION_TEMPLATE = """\
<div>{{ content }}</div>
"""

PREVIEW_TEMPLATE = """\
<html>{{ content }}</html>
"""

PROFILE_BIO_TEMPLATE = """\
<p>{{ bio_text }}</p>
"""


def send_reset_email(user_email: str, reset_token: str) -> str:
    """
    Render a password-reset email safely.
    User input (email, token) is passed as context variables, NOT concatenated.
    """
    return render_template_string(
        RESET_EMAIL_TEMPLATE,
        token=reset_token,
        email=escape(user_email),
    )


def send_welcome_email(username: str) -> str:
    """
    Render a welcome email safely.
    """
    return render_template_string(
        WELCOME_EMAIL_TEMPLATE,
        name=escape(username),
    )


def render_notification(user_input: str) -> str:
    """
    Render a notification div safely.
    """
    return render_template_string(
        NOTIFICATION_TEMPLATE,
        content=escape(user_input),
    )


def preview_email(content: str) -> str:
    """
    Render an email preview safely.
    """
    return render_template_string(
        PREVIEW_TEMPLATE,
        content=escape(content),
    )


def render_profile_bio(bio: str) -> str:
    """
    Render a profile bio safely.
    """
    return render_template_string(
        PROFILE_BIO_TEMPLATE,
        bio_text=escape(bio),
    )

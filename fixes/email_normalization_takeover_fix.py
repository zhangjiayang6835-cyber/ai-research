"""Email identity guard for issue #156.

The vulnerable pattern is using different email-normalization rules for
registration, login, and password reset. That lets an attacker register an
alias that later resolves to a victim account, or request a reset for an alias
and receive a token at an attacker-controlled address. This module uses one
canonical identity key for uniqueness and account lookup, while reset delivery
always goes to the verified address already stored on the account.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}


class InvalidEmail(ValueError):
    """Raised when an email address cannot be used as an identity key."""


class DuplicateEmail(ValueError):
    """Raised when an equivalent verified email is already registered."""


@dataclass(frozen=True)
class Account:
    user_id: str
    email: str
    canonical_email: str


@dataclass(frozen=True)
class PasswordResetDispatch:
    user_id: str
    deliver_to: str
    token: str


def normalize_email_syntax(email: str) -> str:
    """Return a stable display/storage form without provider alias folding."""

    local, domain = _split_email(email)
    return f"{local.strip().lower()}@{domain.strip().lower()}"


def canonical_email(email: str) -> str:
    """Return the account-identity key used for uniqueness and lookup.

    Provider-specific alias folding is intentionally narrow. Gmail ignores dots
    and plus tags in the local part and treats googlemail.com as gmail.com, so
    those variants must collide at registration time. Other domains are not
    plus-folded because doing so would merge identities for providers where
    plus addressing is not an account alias.
    """

    local, domain = _split_email(email)
    local = local.strip().lower()
    domain = domain.strip().lower()

    if domain in GMAIL_DOMAINS:
        domain = "gmail.com"
        local = local.split("+", 1)[0].replace(".", "")
        if not local:
            raise InvalidEmail("gmail identity cannot be empty after normalization")

    return f"{local}@{domain}"


class EmailIdentityStore:
    """In-memory identity index showing the safe account-linking pattern."""

    def __init__(self) -> None:
        self._accounts_by_user_id: dict[str, Account] = {}
        self._accounts_by_canonical_email: dict[str, Account] = {}

    def register(self, user_id: str, verified_email: str) -> Account:
        if not user_id or user_id in self._accounts_by_user_id:
            raise ValueError("user_id must be unique and non-empty")

        stored_email = normalize_email_syntax(verified_email)
        identity_key = canonical_email(verified_email)
        if identity_key in self._accounts_by_canonical_email:
            raise DuplicateEmail("equivalent verified email is already registered")

        account = Account(user_id=user_id, email=stored_email, canonical_email=identity_key)
        self._accounts_by_user_id[user_id] = account
        self._accounts_by_canonical_email[identity_key] = account
        return account

    def find_by_email(self, email: str) -> Account | None:
        return self._accounts_by_canonical_email.get(canonical_email(email))

    def issue_password_reset(
        self,
        requested_email: str,
        token_factory: Callable[[Account], str],
    ) -> PasswordResetDispatch | None:
        """Create a reset dispatch for the verified account email only.

        The caller may accept aliases on input so users can type their common
        Gmail variant, but the reset email must never be sent to that submitted
        string. Sending to the stored verified address closes the zero-click
        takeover path where lookup and delivery use different normalization.
        """

        account = self.find_by_email(requested_email)
        if account is None:
            return None
        return PasswordResetDispatch(
            user_id=account.user_id,
            deliver_to=account.email,
            token=token_factory(account),
        )


def _split_email(email: str) -> tuple[str, str]:
    if not isinstance(email, str):
        raise InvalidEmail("email must be text")
    value = email.strip()
    if not value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise InvalidEmail("email contains control characters")
    if value.count("@") != 1:
        raise InvalidEmail("email must contain exactly one @")
    local, domain = value.split("@", 1)
    if not local or not domain or "." not in domain:
        raise InvalidEmail("email local part and domain are required")
    if any(ch.isspace() for ch in local + domain):
        raise InvalidEmail("email must not contain whitespace")
    return local, domain


__all__ = [
    "Account",
    "DuplicateEmail",
    "EmailIdentityStore",
    "InvalidEmail",
    "PasswordResetDispatch",
    "canonical_email",
    "normalize_email_syntax",
]

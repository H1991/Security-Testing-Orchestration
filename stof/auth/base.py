"""Layer 4 — Authentication Manager: abstract base class + exceptions
every provider raises."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from stof.session.models import Session

if TYPE_CHECKING:
    from playwright.async_api import Page

    from stof.config.schema import UserConfig


class AuthFailedError(Exception):
    """Raised when a login attempt did not result in an authenticated session."""


class AuthExpiredError(Exception):
    """Raised when a session cannot be refreshed in place; the caller
    (Layer 5's session manager) is expected to call `authenticate()`
    again from scratch."""


class AuthProvider(ABC):
    @abstractmethod
    async def authenticate(self, user: "UserConfig", page: "Page") -> Session:
        """Perform login and return a populated Session."""

    @abstractmethod
    async def refresh(self, session: Session, page: "Page") -> Session:
        """Refresh the session. Raise AuthExpiredError if impossible."""

    @abstractmethod
    async def is_authenticated(self, session: Session, page: "Page") -> bool:
        """Check if the current session is still valid."""

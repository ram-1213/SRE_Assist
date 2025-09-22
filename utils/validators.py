"""
Input validation utilities
"""
import re
from typing import Tuple, Optional


class Validators:
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, Optional[str]]:
        """Validate username format"""
        if not username:
            return False, "Username is required"

        if len(username) < 3:
            return False, "Username must be at least 3 characters"

        if len(username) > 30:
            return False, "Username must be less than 30 characters"

        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"

        return True, None

    @staticmethod
    def validate_password(password: str) -> Tuple[bool, Optional[str]]:
        """Validate password strength"""
        if not password:
            return False, "Password is required"

        if len(password) < 6:
            return False, "Password must be at least 6 characters"

        if len(password) > 100:
            return False, "Password is too long"

        # Check for basic password strength
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)

        if not (has_upper or has_lower or has_digit):
            return False, "Password should contain a mix of characters"

        return True, None

    @staticmethod
    def validate_prompt(prompt: str) -> Tuple[bool, Optional[str]]:
        """Validate prompt input"""
        if not prompt:
            return False, "Prompt is required"

        if len(prompt) > 10000:
            return False, "Prompt is too long (max 10000 characters)"

        # Check for obvious prompt injection attempts
        dangerous_patterns = [
            r'<script',
            r'javascript:',
            r'on\w+\s*=',  # Event handlers
            r'<iframe',
            r'<object',
            r'<embed'
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                return False, "Prompt contains potentially dangerous content"

        return True, None

    @staticmethod
    def sanitize_html(text: str) -> str:
        """Remove HTML tags from text"""
        clean = re.compile('<.*?>')
        return re.sub(clean, '', text)

    @staticmethod
    def sanitize_sql(text: str) -> str:
        """Basic SQL sanitization"""
        # Replace dangerous SQL keywords
        dangerous = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'EXEC', 'EXECUTE']
        result = text
        for word in dangerous:
            result = re.sub(rf'\b{word}\b', f'[{word}]', result, flags=re.IGNORECASE)
        return result
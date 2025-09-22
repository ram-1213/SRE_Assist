"""
Authentication and user management
"""
import bcrypt
from database.db_manager import DatabaseManager
import logging

logger = logging.getLogger(__name__)


class AuthManager:
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    def create_user(self, username: str, password: str) -> bool:
        """Create new user account"""
        # Check if user exists
        existing_user = self.db_manager.get_user(username)
        if existing_user:
            return False

        # Hash password and create user
        password_hash = self.hash_password(password)
        return self.db_manager.create_user(username, password_hash)

    def authenticate_user(self, username: str, password: str) -> dict:
        """Authenticate user and return user data if successful"""
        user = self.db_manager.get_user(username)
        if user and self.verify_password(password, user['password_hash']):
            return user
        return None
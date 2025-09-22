"""
Base class for LLM clients
"""
from abc import ABC, abstractmethod
from typing import Optional, List, Dict

class BaseLLMClient(ABC):
    """Base class for all LLM clients"""

    def __init__(self, api_key: str, max_tokens: int = 2048, temperature: float = 0.7):
        self.api_key = api_key
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.client = None

    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate response from LLM"""
        pass

    @abstractmethod
    def generate_with_context(self, prompt: str, context: List[Dict], **kwargs) -> str:
        """Generate response with conversation context"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the client is properly configured"""
        pass

    def sanitize_prompt(self, prompt: str) -> str:
        """Basic prompt sanitization"""
        sanitized = prompt.replace("\\", "\\\\")
        sanitized = sanitized.replace('"', '\\"')
        sanitized = sanitized.replace("'", "\\'")
        return sanitized

"""
Anthropic Claude client implementation
"""
import os
import logging
from typing import List, Dict
from .base_client import BaseLLMClient

logger = logging.getLogger(__name__)

class ClaudeClient(BaseLLMClient):
    """Anthropic Claude client"""

    def __init__(self):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        max_tokens = int(os.getenv("MAX_TOKENS", 2048))
        temperature = float(os.getenv("TEMPERATURE", 0.7))

        super().__init__(api_key=api_key, max_tokens=max_tokens, temperature=temperature)

        if self.api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except Exception as e:
                logger.error(f"Failed to initialize Claude client: {e}")
                self.client = None

    def generate(self, prompt: str, **kwargs) -> str:
        if not self.is_available():
            return "Claude client not available. Please check API key."

        try:
            sanitized_prompt = self.sanitize_prompt(prompt)
            message = self.client.messages.create(
                model=kwargs.get('model', 'claude-3-opus-20240229'),
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system="You are a helpful assistant. Provide safe and secure code without vulnerabilities.",
                messages=[{"role": "user", "content": sanitized_prompt}]
            )
            return message.content[0].text

        except Exception as e:
            logger.error(f"Claude generation error: {e}")
            return f"Error generating response: {str(e)}"

    def generate_with_context(self, prompt: str, context: List[Dict], **kwargs) -> str:
        if not self.is_available():
            return "Claude client not available. Please check API key."

        try:
            messages = []
            for msg in context[-10:]:
                role = "user" if msg['role'] == 'user' else "assistant"
                messages.append({"role": role, "content": msg['content']})
            sanitized_prompt = self.sanitize_prompt(prompt)
            messages.append({"role": "user", "content": sanitized_prompt})

            message = self.client.messages.create(
                model=kwargs.get('model', 'claude-3-opus-20240229'),
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system="You are a helpful assistant. Provide safe and secure code without vulnerabilities. Remember our previous conversation.",
                messages=messages
            )
            return message.content[0].text

        except Exception as e:
            logger.error(f"Claude context generation error: {e}")
            return self.generate(prompt, **kwargs)

    def is_available(self) -> bool:
        return bool(self.api_key and self.client)

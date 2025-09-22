"""
OpenAI GPT client implementation
"""
import os
import logging
from typing import List, Dict
from .base_client import BaseLLMClient

logger = logging.getLogger(__name__)

class OpenAIClient(BaseLLMClient):
    """OpenAI GPT client"""

    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        max_tokens = int(os.getenv("MAX_TOKENS", 2048))
        temperature = float(os.getenv("TEMPERATURE", 0.7))

        super().__init__(api_key=api_key, max_tokens=max_tokens, temperature=temperature)

        if self.api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
                self.client = None

    def generate(self, prompt: str, **kwargs) -> str:
        if not self.is_available():
            return "OpenAI client not available. Please check API key."

        try:
            sanitized_prompt = self.sanitize_prompt(prompt)
            response = self.client.chat.completions.create(
                model=kwargs.get('model', 'gpt-3.5-turbo'),
                messages=[
                    {"role": "system", "content": "You are a helpful assistant. Provide safe and secure code."},
                    {"role": "user", "content": sanitized_prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"OpenAI generation error: {e}")
            return f"Error generating response: {str(e)}"

    def generate_with_context(self, prompt: str, context: List[Dict], **kwargs) -> str:
        if not self.is_available():
            return "OpenAI client not available. Please check API key."

        try:
            messages = [{"role": "system", "content": "You are a helpful assistant. Provide safe and secure code. Remember our previous conversation."}]
            for msg in context[-10:]:
                role = "user" if msg['role'] == 'user' else "assistant"
                messages.append({"role": role, "content": msg['content']})
            sanitized_prompt = self.sanitize_prompt(prompt)
            messages.append({"role": "user", "content": sanitized_prompt})

            response = self.client.chat.completions.create(
                model=kwargs.get('model', 'gpt-3.5-turbo'),
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"OpenAI context generation error: {e}")
            return self.generate(prompt, **kwargs)

    def is_available(self) -> bool:
        return bool(self.api_key and self.client)

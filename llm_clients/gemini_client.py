"""
Google Gemini client implementation
"""
import os
import logging
from typing import List, Dict
from .base_client import BaseLLMClient

logger = logging.getLogger(__name__)

class GeminiClient(BaseLLMClient):
    """Google Gemini client"""

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        max_tokens = int(os.getenv("MAX_TOKENS", 2048))
        temperature = float(os.getenv("TEMPERATURE", 0.7))

        super().__init__(api_key=api_key, max_tokens=max_tokens, temperature=temperature)

        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.client = genai.GenerativeModel('gemini-pro')
            except Exception as e:
                logger.error(f"Failed to initialize Gemini client: {e}")
                self.client = None

    def generate(self, prompt: str, **kwargs) -> str:
        if not self.is_available():
            return "Gemini client not available. Please check API key."

        try:
            sanitized_prompt = self.sanitize_prompt(prompt)
            full_prompt = f"""You are a helpful assistant. Provide safe and secure code without vulnerabilities.

User request: {sanitized_prompt}"""

            response = self.client.generate_content(
                full_prompt,
                generation_config={'temperature': self.temperature, 'max_output_tokens': self.max_tokens}
            )
            return response.text

        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            return f"Error generating response: {str(e)}"

    def generate_with_context(self, prompt: str, context: List[Dict], **kwargs) -> str:
        if not self.is_available():
            return "Gemini client not available. Please check API key."

        try:
            conversation_history = "Previous conversation:\n"
            for msg in context[-10:]:
                role = "User" if msg['role'] == 'user' else "Assistant"
                conversation_history += f"{role}: {msg['content']}\n"

            sanitized_prompt = self.sanitize_prompt(prompt)
            full_prompt = f"""You are a helpful assistant. Provide safe and secure code without vulnerabilities. Remember our previous conversation.

{conversation_history}

User: {sanitized_prompt}"""

            response = self.client.generate_content(
                full_prompt,
                generation_config={'temperature': self.temperature, 'max_output_tokens': self.max_tokens}
            )
            return response.text

        except Exception as e:
            logger.error(f"Gemini context generation error: {e}")
            return self.generate(prompt, **kwargs)

    def is_available(self) -> bool:
        return bool(self.api_key and self.client)

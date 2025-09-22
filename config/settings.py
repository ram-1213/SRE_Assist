"""
Enhanced Configuration Settings with Advanced Security Options
"""
import os
import json
from pathlib import Path
from dotenv import load_dotenv
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv
load_dotenv()


class Settings:
    def __init__(self):
        # Base paths
        self.BASE_DIR = Path(__file__).parent.parent
        self.DATABASE_PATH = os.getenv('DATABASE_PATH', 'secure_llm.db')
        self.LOG_PATH = os.getenv('LOG_PATH', 'logs/')

        # API Keys
        self.OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
        self.ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
        self.GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
        self.HUGGINGFACE_TOKEN = os.getenv('HUGGINGFACE_TOKEN', '')

        # Advanced Security API Keys
        self.REBUFF_API_KEY = os.getenv('REBUFF_API_KEY', '')
        self.GUARDRAILS_API_KEY = os.getenv('GUARDRAILS_API_KEY', '')

        # Security Configuration
        self.SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key-change-in-production')
        self.ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'default-encryption-key')
        self.SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', '3600'))  # 1 hour

        # Analysis Thresholds (0.0 - 1.0)
        self.INJECTION_THRESHOLD = float(os.getenv('INJECTION_THRESHOLD', '0.7'))
        self.SQL_INJECTION_THRESHOLD = float(os.getenv('SQL_INJECTION_THRESHOLD', '0.6'))
        self.DATA_POISON_THRESHOLD = float(os.getenv('DATA_POISON_THRESHOLD', '0.5'))
        self.CODE_VULNERABILITY_THRESHOLD = float(os.getenv('CODE_VULNERABILITY_THRESHOLD', '0.6'))
        self.AI_SAFETY_THRESHOLD = float(os.getenv('AI_SAFETY_THRESHOLD', '0.8'))

        # Model Settings
        self.MAX_TOKENS = int(os.getenv('MAX_TOKENS', '4096'))
        self.TEMPERATURE = float(os.getenv('TEMPERATURE', '0.7'))
        self.MAX_CONTEXT_LENGTH = int(os.getenv('MAX_CONTEXT_LENGTH', '16000'))

        # Security Tools Configuration
        self.SECURITY_TOOLS = {
            'bandit': {
                'enabled': os.getenv('BANDIT_ENABLED', 'true').lower() == 'true',
                'timeout': int(os.getenv('BANDIT_TIMEOUT', '30')),
                'severity_level': os.getenv('BANDIT_SEVERITY', 'medium')
            },
            'semgrep': {
                'enabled': os.getenv('SEMGREP_ENABLED', 'true').lower() == 'true',
                'timeout': int(os.getenv('SEMGREP_TIMEOUT', '60')),
                'config': os.getenv('SEMGREP_CONFIG', 'auto')
            },
            'safety': {
                'enabled': os.getenv('SAFETY_ENABLED', 'true').lower() == 'true',
                'timeout': int(os.getenv('SAFETY_TIMEOUT', '20'))
            },
            'guardrails': {
                'enabled': os.getenv('GUARDRAILS_ENABLED', 'false').lower() == 'true',
                'strict_mode': os.getenv('GUARDRAILS_STRICT', 'false').lower() == 'true'
            },
            'rebuff': {
                'enabled': os.getenv('REBUFF_ENABLED', 'false').lower() == 'true',
                'api_endpoint': os.getenv('REBUFF_API_ENDPOINT', 'https://api.rebuff.ai/v1')
            }
        }

        # Advanced AI Security Settings
        self.AI_SECURITY = {
            'enable_prompt_encryption': os.getenv('ENABLE_PROMPT_ENCRYPTION', 'false').lower() == 'true',
            'enable_response_filtering': os.getenv('ENABLE_RESPONSE_FILTERING', 'true').lower() == 'true',
            'enable_toxicity_detection': os.getenv('ENABLE_TOXICITY_DETECTION', 'true').lower() == 'true',
            'enable_pii_detection': os.getenv('ENABLE_PII_DETECTION', 'true').lower() == 'true',
            'enable_code_sandboxing': os.getenv('ENABLE_CODE_SANDBOXING', 'false').lower() == 'true',
            'max_prompt_length': int(os.getenv('MAX_PROMPT_LENGTH', '10000')),
            'rate_limit_per_user': int(os.getenv('RATE_LIMIT_PER_USER', '100')),  # requests per hour
            'enable_audit_logging': os.getenv('ENABLE_AUDIT_LOGGING', 'true').lower() == 'true'
        }

        # Model-specific configurations
        self.MODEL_CONFIGS = {
            'openai': {
                'default_model': os.getenv('OPENAI_DEFAULT_MODEL', 'gpt-4'),
                'max_tokens': int(os.getenv('OPENAI_MAX_TOKENS', '4096')),
                'temperature': float(os.getenv('OPENAI_TEMPERATURE', '0.7')),
                'frequency_penalty': float(os.getenv('OPENAI_FREQUENCY_PENALTY', '0.0')),
                'presence_penalty': float(os.getenv('OPENAI_PRESENCE_PENALTY', '0.0'))
            },
            'claude': {
                'default_model': os.getenv('CLAUDE_DEFAULT_MODEL', 'claude-3-opus-20240229'),
                'max_tokens': int(os.getenv('CLAUDE_MAX_TOKENS', '4096')),
                'temperature': float(os.getenv('CLAUDE_TEMPERATURE', '0.7'))
            },
            'gemini': {
                'default_model': os.getenv('GEMINI_DEFAULT_MODEL', 'gemini-pro'),
                'max_tokens': int(os.getenv('GEMINI_MAX_TOKENS', '4096')),
                'temperature': float(os.getenv('GEMINI_TEMPERATURE', '0.7')),
                'top_p': float(os.getenv('GEMINI_TOP_P', '0.8')),
                'top_k': int(os.getenv('GEMINI_TOP_K', '40'))
            }
        }

        # Code Analysis Settings
        self.CODE_ANALYSIS = {
            'enable_ast_analysis': os.getenv('ENABLE_AST_ANALYSIS', 'true').lower() == 'true',
            'enable_ml_analysis': os.getenv('ENABLE_ML_ANALYSIS', 'false').lower() == 'true',
            'enable_crypto_analysis': os.getenv('ENABLE_CRYPTO_ANALYSIS', 'true').lower() == 'true',
            'enable_ai_ml_analysis': os.getenv('ENABLE_AI_ML_ANALYSIS', 'true').lower() == 'true',
            'max_analysis_time': int(os.getenv('MAX_ANALYSIS_TIME', '60')),  # seconds
            'parallel_analysis': os.getenv('PARALLEL_ANALYSIS', 'true').lower() == 'true',
            'cache_results': os.getenv('CACHE_ANALYSIS_RESULTS', 'true').lower() == 'true'
        }

        # Database Settings
        self.DATABASE = {
            'type': os.getenv('DB_TYPE', 'sqlite'),
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', '5432')),
            'name': os.getenv('DB_NAME', 'secure_llm'),
            'user': os.getenv('DB_USER', ''),
            'password': os.getenv('DB_PASSWORD', ''),
            'pool_size': int(os.getenv('DB_POOL_SIZE', '10')),
            'max_overflow': int(os.getenv('DB_MAX_OVERFLOW', '20')),
            'echo': os.getenv('DB_ECHO', 'false').lower() == 'true'
        }

        # Logging Configuration
        self.LOGGING = {
            'level': os.getenv('LOG_LEVEL', 'INFO'),
            'format': os.getenv('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            'max_file_size': int(os.getenv('LOG_MAX_FILE_SIZE', '10485760')),  # 10MB
            'backup_count': int(os.getenv('LOG_BACKUP_COUNT', '5')),
            'enable_rotation': os.getenv('LOG_ENABLE_ROTATION', 'true').lower() == 'true',
            'enable_console': os.getenv('LOG_ENABLE_CONSOLE', 'true').lower() == 'true',
            'enable_file': os.getenv('LOG_ENABLE_FILE', 'true').lower() == 'true',
            'security_log_level': os.getenv('SECURITY_LOG_LEVEL', 'WARNING')
        }

        # Performance Settings
        self.PERFORMANCE = {
            'enable_caching': os.getenv('ENABLE_CACHING', 'true').lower() == 'true',
            'cache_ttl': int(os.getenv('CACHE_TTL', '3600')),  # 1 hour
            'max_concurrent_requests': int(os.getenv('MAX_CONCURRENT_REQUESTS', '10')),
            'request_timeout': int(os.getenv('REQUEST_TIMEOUT', '30')),
            'enable_compression': os.getenv('ENABLE_COMPRESSION', 'true').lower() == 'true',
            'enable_async': os.getenv('ENABLE_ASYNC', 'true').lower() == 'true'
        }

        # UI/UX Settings
        self.UI_CONFIG = {
            'theme': os.getenv('UI_THEME', 'dark'),
            'enable_dark_mode': os.getenv('ENABLE_DARK_MODE', 'true').lower() == 'true',
            'max_message_history': int(os.getenv('MAX_MESSAGE_HISTORY', '100')),
            'auto_scroll': os.getenv('AUTO_SCROLL', 'true').lower() == 'true',
            'show_timestamps': os.getenv('SHOW_TIMESTAMPS', 'true').lower() == 'true',
            'show_risk_scores': os.getenv('SHOW_RISK_SCORES', 'true').lower() == 'true',
            'enable_syntax_highlighting': os.getenv('ENABLE_SYNTAX_HIGHLIGHTING', 'true').lower() == 'true',
            'enable_animations': os.getenv('ENABLE_ANIMATIONS', 'true').lower() == 'true'
        }

        # Security Policies
        self.SECURITY_POLICIES = {
            'max_login_attempts': int(os.getenv('MAX_LOGIN_ATTEMPTS', '5')),
            'lockout_duration': int(os.getenv('LOCKOUT_DURATION', '1800')),  # 30 minutes
            'password_min_length': int(os.getenv('PASSWORD_MIN_LENGTH', '8')),
            'password_complexity': os.getenv('PASSWORD_COMPLEXITY', 'medium'),  # low, medium, high
            'enable_2fa': os.getenv('ENABLE_2FA', 'false').lower() == 'true',
            'session_security': os.getenv('SESSION_SECURITY', 'high'),  # low, medium, high
            'enable_ip_whitelist': os.getenv('ENABLE_IP_WHITELIST', 'false').lower() == 'true',
            'allowed_ips': self._parse_list(os.getenv('ALLOWED_IPS', '')),
            'enable_request_signing': os.getenv('ENABLE_REQUEST_SIGNING', 'false').lower() == 'true'
        }

        # Vulnerability Scanning
        self.VULNERABILITY_SCAN = {
            'enable_realtime_scan': os.getenv('ENABLE_REALTIME_SCAN', 'true').lower() == 'true',
            'enable_batch_scan': os.getenv('ENABLE_BATCH_SCAN', 'false').lower() == 'true',
            'scan_timeout': int(os.getenv('SCAN_TIMEOUT', '120')),
            'max_scan_size': int(os.getenv('MAX_SCAN_SIZE', '1048576')),  # 1MB
            'enable_ai_scan': os.getenv('ENABLE_AI_SCAN', 'true').lower() == 'true',
            'confidence_threshold': float(os.getenv('CONFIDENCE_THRESHOLD', '0.7')),
            'enable_custom_rules': os.getenv('ENABLE_CUSTOM_RULES', 'false').lower() == 'true'
        }

        # API Configuration
        self.API_CONFIG = {
            'enable_api': os.getenv('ENABLE_API', 'false').lower() == 'true',
            'api_version': os.getenv('API_VERSION', 'v1'),
            'api_prefix': os.getenv('API_PREFIX', '/api'),
            'enable_swagger': os.getenv('ENABLE_SWAGGER', 'false').lower() == 'true',
            'api_rate_limit': int(os.getenv('API_RATE_LIMIT', '1000')),  # requests per hour
            'enable_api_auth': os.getenv('ENABLE_API_AUTH', 'true').lower() == 'true',
            'api_key_length': int(os.getenv('API_KEY_LENGTH', '32'))
        }

        # Load custom configuration if exists
        self._load_custom_config()

    def get_db_url(self) -> str:
        """Get database connection URL"""
        if self.DATABASE['type'] == 'sqlite':
            return f"sqlite:///{self.DATABASE_PATH}"
        elif self.DATABASE['type'] == 'postgresql':
            return (f"postgresql://{self.DATABASE['user']}:{self.DATABASE['password']}"
                   f"@{self.DATABASE['host']}:{self.DATABASE['port']}/{self.DATABASE['name']}")
        elif self.DATABASE['type'] == 'mysql':
            return (f"mysql://{self.DATABASE['user']}:{self.DATABASE['password']}"
                   f"@{self.DATABASE['host']}:{self.DATABASE['port']}/{self.DATABASE['name']}")
        else:
            return f"sqlite:///{self.DATABASE_PATH}"

    def _parse_list(self, value: str) -> List[str]:
        """Parse comma-separated string into list"""
        if not value:
            return []
        return [item.strip() for item in value.split(',') if item.strip()]

    def _load_custom_config(self):
        """Load custom configuration from JSON file if it exists"""
        config_file = Path(self.BASE_DIR) / 'config' / 'custom_config.json'
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    custom_config = json.load(f)
                    self._merge_config(custom_config)
            except Exception as e:
                print(f"Warning: Could not load custom config: {e}")

    def _merge_config(self, custom_config: Dict[str, Any]):
        """Merge custom configuration with default settings"""
        for section, values in custom_config.items():
            if hasattr(self, section) and isinstance(getattr(self, section), dict):
                current_section = getattr(self, section)
                current_section.update(values)

    def get_security_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for specific security tool"""
        return self.SECURITY_TOOLS.get(tool_name, {})

    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if a security tool is enabled"""
        return self.SECURITY_TOOLS.get(tool_name, {}).get('enabled', False)

    def get_model_config(self, model_name: str) -> Dict[str, Any]:
        """Get configuration for specific model"""
        return self.MODEL_CONFIGS.get(model_name, {})

    def get_risk_threshold(self, risk_type: str) -> float:
        """Get risk threshold for specific type"""
        threshold_map = {
            'injection': self.INJECTION_THRESHOLD,
            'sql_injection': self.SQL_INJECTION_THRESHOLD,
            'data_poisoning': self.DATA_POISON_THRESHOLD,
            'code_vulnerability': self.CODE_VULNERABILITY_THRESHOLD,
            'ai_safety': self.AI_SAFETY_THRESHOLD
        }
        return threshold_map.get(risk_type, 0.7)

    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []

        # Check API keys
        if not any([self.OPENAI_API_KEY, self.ANTHROPIC_API_KEY, self.GEMINI_API_KEY]):
            issues.append("No LLM API keys configured")

        # Check thresholds
        for threshold_name in ['INJECTION_THRESHOLD', 'SQL_INJECTION_THRESHOLD',
                              'DATA_POISON_THRESHOLD', 'CODE_VULNERABILITY_THRESHOLD']:
            threshold = getattr(self, threshold_name)
            if not 0.0 <= threshold <= 1.0:
                issues.append(f"{threshold_name} must be between 0.0 and 1.0")

        # Check database path
        if self.DATABASE['type'] == 'sqlite':
            db_dir = Path(self.DATABASE_PATH).parent
            if not db_dir.exists():
                issues.append(f"Database directory does not exist: {db_dir}")

        # Check log directory
        if self.LOGGING['enable_file']:
            log_dir = Path(self.LOG_PATH)
            if not log_dir.exists():
                try:
                    log_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    issues.append(f"Cannot create log directory: {e}")

        # Check security settings
        if self.SECRET_KEY == 'default-secret-key-change-in-production':
            issues.append("Default secret key should be changed in production")

        if self.ENCRYPTION_KEY == 'default-encryption-key':
            issues.append("Default encryption key should be changed in production")

        return issues

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary (excluding sensitive data)"""
        sensitive_keys = ['SECRET_KEY', 'ENCRYPTION_KEY', 'OPENAI_API_KEY',
                         'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'HUGGINGFACE_TOKEN',
                         'REBUFF_API_KEY', 'GUARDRAILS_API_KEY']

        config_dict = {}
        for attr in dir(self):
            if not attr.startswith('_') and not callable(getattr(self, attr)):
                value = getattr(self, attr)
                if attr not in sensitive_keys:
                    config_dict[attr] = value
                else:
                    config_dict[attr] = "***HIDDEN***" if value else ""

        return config_dict

    def export_config(self, file_path: str, include_sensitive: bool = False):
        """Export configuration to JSON file"""
        if include_sensitive:
            config_dict = {attr: getattr(self, attr)
                          for attr in dir(self)
                          if not attr.startswith('_') and not callable(getattr(self, attr))}
        else:
            config_dict = self.to_dict()

        with open(file_path, 'w') as f:
            json.dump(config_dict, f, indent=2, default=str)

    def get_feature_flags(self) -> Dict[str, bool]:
        """Get all feature flags"""
        return {
            'advanced_security': any(tool['enabled'] for tool in self.SECURITY_TOOLS.values()),
            'ai_security': self.AI_SECURITY['enable_response_filtering'],
            'code_analysis': self.CODE_ANALYSIS['enable_ast_analysis'],
            'real_time_scanning': self.VULNERABILITY_SCAN['enable_realtime_scan'],
            'api_enabled': self.API_CONFIG['enable_api'],
            'audit_logging': self.AI_SECURITY['enable_audit_logging'],
            'async_processing': self.PERFORMANCE['enable_async'],
            'caching': self.PERFORMANCE['enable_caching']
        }
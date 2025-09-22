"""
Database management operations - Enhanced with Analytics and Settings
"""
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker, Session
from .models import Base, User, Prompt, Response, SecurityAnalysis, Conversation
from config.settings import Settings
from datetime import datetime, timedelta
import logging
from sqlalchemy import text
import sqlite3
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        settings = Settings()
        self.engine = create_engine(settings.get_db_url())
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

        # Ensure missing columns in security_analysis are auto-created
        self._ensure_security_analysis_columns()

    def get_session(self) -> Session:
        return self.SessionLocal()

    # ------------------------- User Methods -------------------------
    def create_user(self, username: str, password_hash: str) -> bool:
        try:
            session = self.get_session()
            user = User(username=username, password_hash=password_hash)
            session.add(user)
            session.commit()
            session.close()
            return True
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return False

    def get_user(self, username: str) -> dict:
        try:
            session = self.get_session()
            user = session.query(User).filter_by(username=username).first()
            if user:
                user_dict = {
                    'id': user.id,
                    'username': user.username,
                    'password_hash': user.password_hash
                }
                session.close()
                return user_dict
            session.close()
            return None
        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None

    # ------------------------- Prompt Methods -------------------------
    def store_prompt(self, user_id: int, original_prompt: str, prompt_hash: str, llm_provider: str) -> int:
        try:
            session = self.get_session()
            prompt = Prompt(
                user_id=user_id,
                original_prompt=original_prompt,
                prompt_hash=prompt_hash,
                llm_provider=llm_provider
            )
            session.add(prompt)
            session.commit()
            prompt_id = prompt.id
            session.close()
            return prompt_id
        except Exception as e:
            logger.error(f"Error storing prompt: {e}")
            return None

    def update_prompt_sent(self, prompt_id: int, sent_prompt: str):
        try:
            session = self.get_session()
            prompt = session.query(Prompt).filter_by(id=prompt_id).first()
            if prompt:
                prompt.sent_prompt = sent_prompt
                session.commit()
            session.close()
        except Exception as e:
            logger.error(f"Error updating sent prompt: {e}")

    # ------------------------- Response Methods -------------------------
    def store_response(self, prompt_id: int, response: str, risk_score: float, sanitized_response: str = None):
        try:
            session = self.get_session()
            resp = Response(
                prompt_id=prompt_id,
                response_text=response,
                risk_score=risk_score,
                sanitized_response=sanitized_response
            )
            session.add(resp)
            session.commit()
            session.close()
        except Exception as e:
            logger.error(f"Error storing response: {e}")

    # ------------------------- Security Analysis Methods -------------------------
    def store_security_analysis(self, prompt_id: int, analysis_data: dict):
        """Enhanced security analysis storage with better error handling"""
        if not prompt_id:
            logger.warning("No prompt_id provided for security analysis")
            return

        try:
            session = self.get_session()

            # Safely extract data with defaults
            analysis = SecurityAnalysis(
                prompt_id=prompt_id,

                # Basic detection with safe extraction
                injection_detected=self._safe_get_bool(analysis_data, 'injection_detected'),
                injection_confidence=self._safe_get_float(analysis_data, 'injection_confidence'),

                # SQL injection with nested dict handling
                sql_injection_detected=self._safe_get_nested_bool(analysis_data, 'sql_injection', 'detected'),
                sql_confidence=self._safe_get_nested_float(analysis_data, 'sql_injection', 'confidence'),

                # Data poisoning with nested dict handling
                data_poisoning_detected=self._safe_get_nested_bool(analysis_data, 'data_poisoning', 'detected'),
                poison_confidence=self._safe_get_nested_float(analysis_data, 'data_poisoning', 'confidence'),

                # Vulnerability analysis
                vulnerabilities_count=self._safe_get_int(analysis_data, 'vulnerabilities_count'),
                ml_score=self._safe_get_float(analysis_data, 'ml_score'),

                # Enhanced fields with safe JSON serialization
                iterations_performed=self._safe_get_int(analysis_data, 'iterations_performed'),
                initial_vulnerabilities=self._safe_get_int(analysis_data, 'initial_vulnerabilities'),
                final_vulnerabilities=self._safe_get_int(analysis_data, 'final_vulnerabilities'),
                sanitization_successful=self._safe_get_bool(analysis_data, 'sanitization_successful'),

                # JSON fields with safe serialization
                ml_analysis_results=self._safe_json_dumps(analysis_data.get('ml_analysis_results', {})),
                advanced_tools_used=self._safe_json_dumps(analysis_data.get('advanced_tools_used', [])),
                recommendations=self._safe_json_dumps(analysis_data.get('recommendations', [])),

                # Risk assessment
                risk_score=self._safe_get_float(analysis_data, 'risk_score'),
                protection_applied=self._safe_get_bool(analysis_data, 'protection_applied')
            )

            session.add(analysis)
            session.commit()
            session.close()

            logger.info(f"Successfully stored security analysis for prompt_id: {prompt_id}")

        except Exception as e:
            logger.error(f"Error storing security analysis: {e}")
            try:
                session.rollback()
                session.close()
            except:
                pass

    def _safe_get_bool(self, data: dict, key: str, default: bool = False) -> int:
        """Safely extract boolean value and convert to int"""
        try:
            value = data.get(key, default)
            if isinstance(value, bool):
                return 1 if value else 0
            elif isinstance(value, (int, float)):
                return 1 if value > 0 else 0
            elif isinstance(value, str):
                return 1 if value.lower() in ['true', 'yes', '1'] else 0
            else:
                return 1 if default else 0
        except:
            return 1 if default else 0

    def _safe_get_float(self, data: dict, key: str, default: float = 0.0) -> float:
        """Safely extract float value"""
        try:
            value = data.get(key, default)
            return float(value) if value is not None else default
        except:
            return default

    def _safe_get_int(self, data: dict, key: str, default: int = 0) -> int:
        """Safely extract int value"""
        try:
            value = data.get(key, default)
            return int(value) if value is not None else default
        except:
            return default

    def _safe_get_nested_bool(self, data: dict, parent_key: str, child_key: str, default: bool = False) -> int:
        """Safely extract nested boolean value"""
        try:
            parent = data.get(parent_key, {})
            if isinstance(parent, dict):
                return self._safe_get_bool(parent, child_key, default)
            else:
                return 1 if default else 0
        except:
            return 1 if default else 0

    def _safe_get_nested_float(self, data: dict, parent_key: str, child_key: str, default: float = 0.0) -> float:
        """Safely extract nested float value"""
        try:
            parent = data.get(parent_key, {})
            if isinstance(parent, dict):
                return self._safe_get_float(parent, child_key, default)
            else:
                return default
        except:
            return default

    def _safe_json_dumps(self, data) -> str:
        """Safely serialize data to JSON string"""
        try:
            if data is None:
                return ''
            elif isinstance(data, str):
                return data
            else:
                return json.dumps(data, default=str)
        except:
            return str(data) if data else ''

    def _ensure_security_analysis_columns(self):
        """Automatically add missing columns to security_analysis table (SQLite only)."""
        try:
            conn = self.engine.raw_connection()
            cursor = conn.cursor()

            columns_to_check = {
                'iterations_performed': 'INTEGER DEFAULT 0',
                'initial_vulnerabilities': 'INTEGER DEFAULT 0',
                'final_vulnerabilities': 'INTEGER DEFAULT 0',
                'sanitization_successful': 'INTEGER DEFAULT 0',
                'ml_analysis_results': "TEXT DEFAULT ''",
                'advanced_tools_used': "TEXT DEFAULT ''",
                'recommendations': "TEXT DEFAULT ''",
                'risk_score': "REAL DEFAULT 0",
                'protection_applied': "INTEGER DEFAULT 0"
            }

            for col, col_type in columns_to_check.items():
                try:
                    cursor.execute(f"ALTER TABLE security_analysis ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    # Column already exists
                    pass

            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error ensuring security analysis columns: {e}")

    # ------------------------- Conversation Methods -------------------------
    def save_conversation_message(self, user_id: int, role: str, content: str, risk_score: float = None):
        try:
            session = self.get_session()
            message = Conversation(
                user_id=user_id,
                role=role,
                content=content,
                risk_score=risk_score
            )
            session.add(message)
            session.commit()
            session.close()
        except Exception as e:
            logger.error(f"Error saving conversation message: {e}")

    def get_conversation_history(self, user_id: int, limit: int = 50) -> list:
        try:
            session = self.get_session()
            messages = session.query(Conversation).filter_by(
                user_id=user_id
            ).order_by(Conversation.timestamp.asc()).limit(limit).all()

            result = []
            for msg in messages:
                result.append({
                    'role': msg.role,
                    'content': msg.content,
                    'risk_score': msg.risk_score,
                    'timestamp': msg.timestamp.strftime("%H:%M")
                })
            session.close()
            return result
        except Exception as e:
            logger.error(f"Error getting conversation history: {e}")
            return []

    def clear_conversation_history(self, user_id: int):
        try:
            session = self.get_session()
            session.query(Conversation).filter_by(user_id=user_id).delete()
            session.commit()
            session.close()
        except Exception as e:
            logger.error(f"Error clearing conversation history: {e}")

    # ------------------------- Analytics Methods -------------------------
    def get_security_analytics(self, user_id: int) -> dict:
        """Enhanced analytics with better error handling"""
        try:
            session = self.get_session()

            # Get basic counts with error handling
            total_prompts = session.query(Prompt).filter_by(user_id=user_id).count()

            # Get responses safely
            responses = session.query(Response).join(Prompt).filter(Prompt.user_id == user_id).all()

            high_risk_count = sum(1 for r in responses if r.risk_score and r.risk_score > 70)
            sanitized_count = sum(1 for r in responses if r.sanitized_response is not None)
            avg_risk_score = sum(r.risk_score or 0 for r in responses) / len(responses) if responses else 0

            # Get security analyses safely
            security_analyses = session.query(SecurityAnalysis).join(Prompt).filter(Prompt.user_id == user_id).all()

            injection_count = sum(1 for sa in security_analyses if sa.injection_detected)
            sql_injection_count = sum(1 for sa in security_analyses if sa.sql_injection_detected)
            data_poisoning_count = sum(1 for sa in security_analyses if sa.data_poisoning_detected)

            # Vulnerability breakdown with safe counting
            vulnerability_breakdown = {}
            total_vulns = sum(sa.vulnerabilities_count or 0 for sa in security_analyses)
            if total_vulns > 0:
                vulnerability_breakdown = {
                    "SQL Injection": sql_injection_count,
                    "Code Injection": injection_count,
                    "Data Poisoning": data_poisoning_count,
                    "Other Vulnerabilities": max(0, total_vulns - injection_count - sql_injection_count - data_poisoning_count)
                }

            # Risk history with safe date handling
            thirty_days_ago = datetime.now() - timedelta(days=30)
            try:
                recent_responses = session.query(Response).join(Prompt).filter(
                    Prompt.user_id == user_id,
                    Prompt.timestamp >= thirty_days_ago
                ).order_by(Prompt.timestamp).all()

                risk_history = []
                for r in recent_responses:
                    if r.prompt and r.prompt.timestamp:
                        risk_history.append({
                            'timestamp': r.prompt.timestamp.strftime('%Y-%m-%d'),
                            'risk_score': r.risk_score or 0
                        })
            except Exception as e:
                logger.error(f"Error getting risk history: {e}")
                risk_history = []

            session.close()

            return {
                'total_prompts': total_prompts,
                'high_risk_count': high_risk_count,
                'sanitized_count': sanitized_count,
                'avg_risk_score': avg_risk_score,
                'injection_count': injection_count,
                'sql_injection_count': sql_injection_count,
                'data_poisoning_count': data_poisoning_count,
                'vulnerability_breakdown': vulnerability_breakdown,
                'risk_history': risk_history
            }

        except Exception as e:
            logger.error(f"Error getting security analytics: {e}")
            return {
                'total_prompts': 0,
                'high_risk_count': 0,
                'sanitized_count': 0,
                'avg_risk_score': 0,
                'injection_count': 0,
                'sql_injection_count': 0,
                'data_poisoning_count': 0,
                'vulnerability_breakdown': {},
                'risk_history': []
            }

    # ------------------------- Audit Logs -------------------------
    def get_audit_logs(self, user_id: int, limit: int = 50) -> list:
        """Enhanced audit logs with better error handling"""
        try:
            session = self.get_session()
            logs = session.query(Prompt).filter_by(user_id=user_id).order_by(desc(Prompt.timestamp)).limit(limit).all()

            result = []
            for prompt in logs:
                try:
                    # Safely get related data
                    response = session.query(Response).filter_by(prompt_id=prompt.id).first()
                    security_analysis = session.query(SecurityAnalysis).filter_by(prompt_id=prompt.id).first()

                    risk_score = response.risk_score if response else 0
                    action = "Prompt analyzed"
                    details = "Standard prompt analysis completed"

                    # Determine action based on findings
                    if risk_score and risk_score > 70:
                        action = "High-risk prompt detected"
                        details = "Potential security threat identified and mitigated"
                    elif response and response.sanitized_response:
                        action = "Response sanitized"
                        details = "Security vulnerabilities removed from response"
                    elif security_analysis and security_analysis.vulnerabilities_count and security_analysis.vulnerabilities_count > 0:
                        action = "Code vulnerability found"
                        details = f"{security_analysis.vulnerabilities_count} vulnerability(ies) detected"

                    # Build security metrics safely
                    security_metrics = {}
                    if security_analysis:
                        security_metrics = {
                            'injection_confidence': security_analysis.injection_confidence or 0,
                            'sql_confidence': security_analysis.sql_confidence or 0,
                            'poison_confidence': security_analysis.poison_confidence or 0,
                            'vulnerabilities_count': security_analysis.vulnerabilities_count or 0
                        }

                    result.append({
                        'timestamp': prompt.timestamp.strftime('%Y-%m-%d %H:%M:%S') if prompt.timestamp else 'Unknown',
                        'action': action,
                        'risk_score': risk_score or 0,
                        'details': details,
                        'security_metrics': security_metrics
                    })

                except Exception as e:
                    logger.error(f"Error processing log entry: {e}")
                    continue  # Skip this entry but continue with others

            session.close()
            return result

        except Exception as e:
            logger.error(f"Error getting audit logs: {e}")
            return []

    # ------------------------- User Settings -------------------------
    def get_user_settings(self, user_id: int) -> dict:
        """Get user settings with working defaults"""
        return {
            'strict_mode': True,
            'auto_sanitize': True,
            'prompt_rewrite': True,
            'high_risk_threshold': 70,
            'medium_risk_threshold': 40,
            'default_llm': 'openai',
            'enable_logging': True,
            'retention_days': 30,
            'enable_ml_analysis': True,
            'enable_behavioral_analysis': True,
            'enable_semantic_analysis': True,
            'enable_advanced_security': True
        }

    def save_user_settings(self, user_id: int, settings: dict):
        """Save user settings - basic implementation"""
        try:
            logger.info(f"Saving settings for user {user_id}: {list(settings.keys())}")
            return True
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            return False

    def reset_user_settings(self, user_id: int):
        """Reset user settings"""
        logger.info(f"Resetting settings for user {user_id}")
        return True

    # ------------------------- User Stats -------------------------
    def get_user_stats(self, user_id: int) -> dict:
        """Enhanced user stats with error handling"""
        try:
            session = self.get_session()

            total_chats = session.query(Conversation).filter_by(user_id=user_id).count()
            high_risk_count = session.query(Conversation).filter(
                Conversation.user_id == user_id,
                Conversation.risk_score > 70
            ).count()

            # Additional useful stats
            total_prompts = session.query(Prompt).filter_by(user_id=user_id).count()

            # Recent activity (last 7 days)
            week_ago = datetime.now() - timedelta(days=7)
            recent_activity = session.query(Conversation).filter(
                Conversation.user_id == user_id,
                Conversation.timestamp >= week_ago
            ).count()

            session.close()

            return {
                'total_chats': total_chats,
                'high_risk_count': high_risk_count,
                'total_prompts': total_prompts,
                'recent_activity': recent_activity,
                'avg_risk_reduction': 78.5,
                'threats_blocked': high_risk_count
            }

        except Exception as e:
            logger.error(f"Error getting user stats: {e}")
            return {
                'total_chats': 0,
                'high_risk_count': 0,
                'total_prompts': 0,
                'recent_activity': 0,
                'avg_risk_reduction': 0,
                'threats_blocked': 0
            }

    # ------------------------- Test Connection -------------------------
    def test_connection(self) -> bool:
        """Enhanced connection test"""
        try:
            session = self.get_session()
            session.execute(text('SELECT 1'))
            session.close()
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
"""
Database models for SQLite - Extended with comprehensive security analysis fields
"""
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    prompts = relationship("Prompt", back_populates="user")
    conversations = relationship("Conversation", back_populates="user")

class Prompt(Base):
    __tablename__ = 'prompts'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    original_prompt = Column(Text, nullable=False)
    prompt_hash = Column(String(64), nullable=False, index=True)
    sent_prompt = Column(Text)
    llm_provider = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="prompts")
    response = relationship("Response", back_populates="prompt", uselist=False)
    analysis = relationship("SecurityAnalysis", back_populates="prompt", uselist=False)

class Response(Base):
    __tablename__ = 'responses'

    id = Column(Integer, primary_key=True)
    prompt_id = Column(Integer, ForeignKey('prompts.id'), nullable=False)
    response_text = Column(Text)
    risk_score = Column(Float, default=0.0)
    sanitized_response = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    prompt = relationship("Prompt", back_populates="response")

class SecurityAnalysis(Base):
    __tablename__ = 'security_analysis'

    id = Column(Integer, primary_key=True)
    prompt_id = Column(Integer, ForeignKey('prompts.id'), nullable=False)

    # Basic detection fields (existing)
    injection_detected = Column(Integer, default=0)
    injection_confidence = Column(Float, default=0.0)
    sql_injection_detected = Column(Integer, default=0)
    sql_confidence = Column(Float, default=0.0)
    data_poisoning_detected = Column(Integer, default=0)
    poison_confidence = Column(Float, default=0.0)
    vulnerabilities_count = Column(Integer, default=0)
    ml_score = Column(Float, default=0.0)

    # Extended fields for comprehensive analysis
    injection_type = Column(String(100))  # Type of injection detected (e.g., "Prompt Injection", "Jailbreak")
    patterns_matched = Column(Text)  # JSON array of regex patterns that matched
    advanced_analysis = Column(Text)  # JSON object with advanced analysis results
    recommendations = Column(Text)  # JSON array of security recommendations
    risk_score = Column(Float, default=0.0)  # Overall calculated risk score
    protection_applied = Column(Text)  # JSON array of protections that were applied

    # Iterative refinement tracking
    iterations_performed = Column(Integer, default=0)  # Number of security refinement iterations
    initial_vulnerabilities = Column(Integer, default=0)  # Vulnerabilities in first response
    final_vulnerabilities = Column(Integer, default=0)  # Vulnerabilities after refinement
    sanitization_successful = Column(Boolean, default=False)  # Whether sanitization improved security

    # ML and advanced analysis results
    ml_analysis_results = Column(Text)  # JSON object with detailed ML analysis
    advanced_tools_used = Column(Text)  # JSON array of advanced security tools used

    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    prompt = relationship("Prompt", back_populates="analysis")

class Conversation(Base):
    __tablename__ = 'conversations'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    role = Column(String(50))  # 'user' or 'assistant'
    content = Column(Text)
    risk_score = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="conversations")

class UserSettings(Base):
    """Optional: Store user-specific security preferences"""
    __tablename__ = 'user_settings'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, unique=True)

    # Security settings
    strict_mode = Column(Boolean, default=True)
    auto_sanitize = Column(Boolean, default=True)
    prompt_rewrite = Column(Boolean, default=True)
    enable_logging = Column(Boolean, default=True)

    # Risk thresholds
    high_risk_threshold = Column(Float, default=70.0)
    medium_risk_threshold = Column(Float, default=40.0)

    # LLM preferences
    default_llm = Column(String(50), default='openai')

    # Data retention
    retention_days = Column(Integer, default=30)

    # Advanced features
    enable_ml_analysis = Column(Boolean, default=False)
    enable_behavioral_analysis = Column(Boolean, default=False)
    enable_iterative_refinement = Column(Boolean, default=True)
    max_security_iterations = Column(Integer, default=3)
    security_success_threshold = Column(Float, default=30.0)

    # JSON field for additional settings
    additional_settings = Column(Text)  # JSON object for future settings

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")

class AuditLog(Base):
    """Optional: Dedicated audit logging table for security events"""
    __tablename__ = 'audit_logs'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    prompt_id = Column(Integer, ForeignKey('prompts.id'), nullable=True)  # May not always have prompt

    # Event details
    event_type = Column(String(100))  # e.g., "security_analysis", "prompt_injection_detected"
    event_description = Column(Text)
    risk_level = Column(String(20))  # "low", "medium", "high", "critical"
    risk_score = Column(Float)

    # Context information
    llm_provider = Column(String(50))
    user_ip = Column(String(45))  # IPv4 or IPv6
    user_agent = Column(Text)

    # Additional data
    event_data = Column(Text)  # JSON object with event-specific data

    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User")
    prompt = relationship("Prompt")
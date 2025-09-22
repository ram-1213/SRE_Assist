"""
Enhanced Prompt injection and security analysis with advanced tools integration
"""
import re
import hashlib
import html
import unicodedata
from typing import Dict, List, Optional
from difflib import SequenceMatcher
from database.db_manager import DatabaseManager
from .advanced_security import AdvancedSecurityManager, SecurityCheckResult
from database.models import SecurityAnalysis
import logging
import json
logger = logging.getLogger(__name__)


class EnhancedPromptAnalyzer:
    def __init__(self, db_manager: DatabaseManager, strict_mode: bool = False):
        self.db_manager = db_manager
        self.strict_mode = strict_mode

        # Initialize advanced security manager
        self.advanced_security = AdvancedSecurityManager()

        # Compile regex patterns for performance
        self.injection_patterns = [
            (re.compile(p, re.IGNORECASE), weight) for p, weight in [
                (r"ignore\s+previous\s+instructions", 25),
                (r"disregard\s+all\s+prior", 25),
                (r"forget\s+everything", 25),
                (r"new\s+instructions:", 25),
                (r"system:\s*", 25),
                (r"admin\s+mode", 25),
                (r"developer\s+mode", 25),
                (r"bypass\s+security", 25),
                (r"reveal\s+system\s+prompt", 25),
                (r"show\s+me\s+your\s+instructions", 25),
                (r"what\s+are\s+your\s+rules", 25),
                (r"</prompt>", 25),
                (r"<prompt>", 25),
                (r"\[INST\]", 25),
                (r"\[/INST\]", 25),
                (r"###\s*Instruction:", 25),
                (r"###\s*System:", 25),
                # Additional advanced patterns
                (r"act\s+as\s+(?:a\s+)?different", 20),
                (r"pretend\s+you\s+are", 20),
                (r"you\s+are\s+now", 20),
                (r"switch\s+to\s+.*\s+mode", 20),
                (r"enable\s+.*\s+mode", 20),
                (r"dan\s+mode", 30),
                (r"jailbreak", 30),
            ]
        ]

        self.sql_patterns = [
            (re.compile(p, re.IGNORECASE), weight) for p, weight in [
                (r"(\bUNION\b.*\bSELECT\b)", 30),
                (r"(\bDROP\b.*\bTABLE\b)", 30),
                (r"(\bINSERT\b.*\bINTO\b)", 30),
                (r"(\bDELETE\b.*\bFROM\b)", 30),
                (r"(\bUPDATE\b.*\bSET\b)", 30),
                (r"(--|\#|\/\*)", 30),
                (r"(\bOR\b\s+\d+\s*=\s*\d+)", 30),
                (r"(\bAND\b\s+\d+\s*=\s*\d+)", 30),
                (r"(;\s*\bEXEC\b)", 30),
                (r"(xp_cmdshell)", 30),
                (r"(sp_executesql)", 30),
                (r"(\bWAITFOR\b.*\bDELAY\b)", 30),
                # Additional SQL patterns
                (r"(\bSELECT\b.*\bFROM\b.*\bINFORMATION_SCHEMA\b)", 35),
                (r"(\bSLEEP\s*\(\s*\d+\s*\))", 25),
                (r"(\bBENCHMARK\s*\()", 25),
            ]
        ]

        self.poison_patterns = [
            (re.compile(p, re.IGNORECASE), weight) for p, weight in [
                (r"<script[^>]*>.*?</script>", 35),
                (r"javascript:", 35),
                (r"data:text/html", 35),
                (r"vbscript:", 35),
                (r"onload\s*=", 35),
                (r"onerror\s*=", 35),
                (r"onclick\s*=", 35),
                (r"<iframe", 35),
                (r"<embed", 35),
                (r"<object", 35),
                (r"base64,", 20),
                (r"\\x[0-9a-fA-F]{2}", 35),
                (r"\\u[0-9a-fA-F]{4}", 35),
                (r"%3Cscript", 35),
                (r"eval\(", 35),
                (r"exec\(", 35),
                # Additional poisoning patterns
                (r"String\.fromCharCode", 30),
                (r"document\.cookie", 30),
                (r"window\.location", 30),
                (r"localStorage\.", 30),
            ]
        ]

    def _normalize(self, text: str) -> str:
        """Normalize text for consistent scanning."""
        text = html.unescape(text)  # Decode HTML entities
        text = unicodedata.normalize("NFKC", text)  # Normalize Unicode
        return text.strip()

    def analyze_prompt(self, prompt: str) -> Dict:
        """Analyze prompt for prompt injection attempts with pattern matching."""
        prompt = self._normalize(prompt)
        result = {
            'injection_detected': False,
            'injection_confidence': 0,
            'injection_type': None,
            'patterns_matched': []
        }

        for pattern, weight in self.injection_patterns:
            if pattern.search(prompt):
                result['injection_detected'] = True
                result['injection_confidence'] = min(result['injection_confidence'] + weight, 100)
                result['patterns_matched'].append(pattern.pattern)
                if self.strict_mode and result['injection_confidence'] >= 50:
                    break

        if result['injection_detected']:
            result['injection_type'] = 'Prompt Injection Attempt'

        return result



    def _store_analysis(self, prompt: str, analysis_result: Dict, prompt_id: int = None):
        """Store comprehensive analysis results in the extended SecurityAnalysis table."""
        try:
            if not prompt_id:
                # If no prompt_id provided, we need to find it or create a prompt record
                # This assumes you have access to user_id somehow
                logger.warning("No prompt_id provided for analysis storage")
                return

            session = self.db_manager.get_session()

            # Check if SecurityAnalysis already exists for this prompt
            existing_analysis = session.query(SecurityAnalysis).filter_by(prompt_id=prompt_id).first()

            if existing_analysis:
                # Update existing record with comprehensive analysis
                existing_analysis.injection_type = analysis_result.get('injection_type')
                existing_analysis.patterns_matched = json.dumps(analysis_result.get('patterns_matched', []))
                existing_analysis.advanced_analysis = json.dumps(analysis_result.get('advanced_analysis', {}))
                existing_analysis.recommendations = json.dumps(analysis_result.get('recommendations', []))
                existing_analysis.risk_score = analysis_result.get('risk_score', 0.0)

                # Update existing basic fields if they exist
                if 'injection_detected' in analysis_result:
                    existing_analysis.injection_detected = 1 if analysis_result['injection_detected'] else 0
                if 'injection_confidence' in analysis_result:
                    existing_analysis.injection_confidence = analysis_result['injection_confidence']

                # Update SQL injection fields
                sql_injection = analysis_result.get('sql_injection', {})
                if sql_injection:
                    existing_analysis.sql_injection_detected = 1 if sql_injection.get('detected') else 0
                    existing_analysis.sql_confidence = sql_injection.get('confidence', 0)

                # Update data poisoning fields
                data_poisoning = analysis_result.get('data_poisoning', {})
                if data_poisoning:
                    existing_analysis.data_poisoning_detected = 1 if data_poisoning.get('detected') else 0
                    existing_analysis.poison_confidence = data_poisoning.get('confidence', 0)

            else:
                # Create new SecurityAnalysis record
                analysis_record = SecurityAnalysis(
                    prompt_id=prompt_id,

                    # Basic detection fields
                    injection_detected=1 if analysis_result.get('injection_detected') else 0,
                    injection_confidence=analysis_result.get('injection_confidence', 0),
                    injection_type=analysis_result.get('injection_type'),

                    # SQL injection
                    sql_injection_detected=1 if analysis_result.get('sql_injection', {}).get('detected') else 0,
                    sql_confidence=analysis_result.get('sql_injection', {}).get('confidence', 0),

                    # Data poisoning
                    data_poisoning_detected=1 if analysis_result.get('data_poisoning', {}).get('detected') else 0,
                    poison_confidence=analysis_result.get('data_poisoning', {}).get('confidence', 0),

                    # Comprehensive analysis fields
                    patterns_matched=json.dumps(analysis_result.get('patterns_matched', [])),
                    advanced_analysis=json.dumps(analysis_result.get('advanced_analysis', {})),
                    recommendations=json.dumps(analysis_result.get('recommendations', [])),
                    risk_score=analysis_result.get('risk_score', 0.0),

                    # Other fields
                    vulnerabilities_count=analysis_result.get('vulnerabilities_count', 0),
                    ml_score=analysis_result.get('ml_score', 0)
                )

                session.add(analysis_record)

            session.commit()
            session.close()

            logger.info(f"Stored comprehensive analysis for prompt_id: {prompt_id}")

        except Exception as e:
            logger.error(f"Failed to store comprehensive analysis: {e}")
            # Don't raise exception - analysis storage failure shouldn't break the main flow

    def store_protection_applied(self, prompt_id: int, protection_data: Dict):
        """Store information about protections applied to a prompt."""
        try:
            session = self.db_manager.get_session()

            # Update or create SecurityAnalysis record with protection info
            analysis = session.query(SecurityAnalysis).filter_by(prompt_id=prompt_id).first()

            if analysis:
                analysis.protection_applied = json.dumps(protection_data.get('protections', []))
                session.commit()
                logger.info(f"Stored protection data for prompt_id: {prompt_id}")

            session.close()

        except Exception as e:
            logger.error(f"Failed to store protection data: {e}")

    def check_sql_injection(self, prompt: str) -> Dict:
        """Check for SQL injection patterns."""
        prompt = self._normalize(prompt)
        result = {'detected': False, 'confidence': 0, 'patterns': [], 'pattern': None}

        for pattern, weight in self.sql_patterns:
            if pattern.search(prompt):
                result['detected'] = True
                result['confidence'] = min(result['confidence'] + weight, 100)
                result['patterns'].append(pattern.pattern)
                if self.strict_mode and result['confidence'] >= 50:
                    break

        if result['patterns']:
            result['pattern'] = result['patterns'][0]

        return result

    def check_data_poisoning(self, prompt: str) -> Dict:
        """Check for data poisoning attempts."""
        prompt = self._normalize(prompt)
        result = {'detected': False, 'confidence': 0, 'patterns': [], 'type': None}

        for pattern, weight in self.poison_patterns:
            if pattern.search(prompt):
                result['detected'] = True
                result['confidence'] = min(result['confidence'] + weight, 100)
                result['patterns'].append(pattern.pattern)
                result['type'] = 'Data Poisoning Attempt'

        # Suspicious encoding check
        if any(enc in prompt.lower() for enc in ['base64', '\\x', '\\u', '%']):
            result['confidence'] = min(result['confidence'] + 20, 100)
            if result['confidence'] > 50:
                result['detected'] = True
                result['type'] = 'Encoded Payload Detected'

        return result

    def compare_prompts(self, original: str, sent: str) -> Dict:
        """Compare original and sent prompts for manipulation."""
        original_norm = self._normalize(original)
        sent_norm = self._normalize(sent)

        original_hash = hashlib.sha256(original_norm.encode()).hexdigest()
        sent_hash = hashlib.sha256(sent_norm.encode()).hexdigest()

        similarity = SequenceMatcher(None, original_norm, sent_norm).ratio()

        result = {
            'modified': original_hash != sent_hash,
            'similarity': round(similarity, 3),
            'additions': [],
            'removals': []
        }

        if result['modified']:
            original_words = set(original_norm.split())
            sent_words = set(sent_norm.split())
            result['additions'] = list(sent_words - original_words)
            result['removals'] = list(original_words - sent_words)

        return result

    def analyze_all(self, prompt: str) -> Dict:
        """Run all basic checks and return combined results."""
        return {
            'prompt_injection': self.analyze_prompt(prompt),
            'sql_injection': self.check_sql_injection(prompt),
            'data_poisoning': self.check_data_poisoning(prompt)
        }

    def analyze_prompt_comprehensive(self, prompt: str, context: Optional[Dict] = None, prompt_id: int = None) -> Dict:
        # Normalize the prompt
        prompt = self._normalize(prompt)

        # Initialize result
        result = {
            'injection_detected': False,
            'injection_confidence': 0,
            'injection_type': None,
            'patterns_matched': [],
            'sql_injection': None,
            'data_poisoning': None,
            'advanced_analysis': {},
            'risk_score': 0,
            'recommendations': []
        }

        # 1. Run all basic pattern-based analyses
        basic_results = self.analyze_all(prompt)

        # Merge prompt injection results
        prompt_injection = basic_results['prompt_injection']
        result.update(prompt_injection)

        # Add SQL injection results
        result['sql_injection'] = basic_results['sql_injection']

        # Add data poisoning results
        result['data_poisoning'] = basic_results['data_poisoning']

        # Calculate initial risk score from pattern matching
        pattern_risk = 0
        if prompt_injection['injection_detected']:
            pattern_risk += prompt_injection['injection_confidence'] * 0.4
        if basic_results['sql_injection']['detected']:
            pattern_risk += basic_results['sql_injection']['confidence'] * 0.3
        if basic_results['data_poisoning']['detected']:
            pattern_risk += basic_results['data_poisoning']['confidence'] * 0.3

        # 2. Advanced security analysis if available
        try:
            advanced_result = self.advanced_security.analyze_prompt(prompt, context)

            # Store advanced analysis details
            result['advanced_analysis'] = {
                'passed': advanced_result.passed,
                'risk_score': advanced_result.risk_score,
                'issues': advanced_result.issues,
                'tools_used': list(advanced_result.details.keys()),
                'recommendations': advanced_result.recommendations,
                'details': advanced_result.details
            }

            # Combine risk scores (weighted average)
            # Weight advanced tools higher if available
            if advanced_result.details:
                result['risk_score'] = (pattern_risk * 0.3 + advanced_result.risk_score * 0.7)
            else:
                result['risk_score'] = pattern_risk

            # Update detection status if advanced tools found issues
            if not advanced_result.passed:
                result['injection_detected'] = True
                result['injection_confidence'] = max(
                    result['injection_confidence'],
                    advanced_result.risk_score
                )

                # Add specific detection types from advanced analysis
                if any('jailbreak' in issue.lower() for issue in advanced_result.issues):
                    result['injection_type'] = 'Jailbreak Attempt'
                elif any('injection' in issue.lower() for issue in advanced_result.issues):
                    if not result['injection_type']:
                        result['injection_type'] = 'Advanced Prompt Injection'
                elif any('pii' in issue.lower() for issue in advanced_result.issues):
                    result['injection_type'] = 'PII Exposure Risk'

            # Combine recommendations
            result['recommendations'].extend(advanced_result.recommendations)

        except Exception as e:
            logger.error(f"Advanced security analysis error: {e}")
            # Fallback to pattern-based risk score
            result['risk_score'] = pattern_risk

        # 3. Add general recommendations based on all findings
        if not result['recommendations']:
            if result['risk_score'] < 30:
                result['recommendations'].append("Prompt appears safe for processing")
            elif result['risk_score'] < 70:
                result['recommendations'].append("Review prompt carefully before processing")
            else:
                result['recommendations'].append("High-risk prompt - consider blocking or sanitizing")

        # 4. Store analysis in database for audit
        if prompt_id:
            self._store_analysis(prompt, result, prompt_id)

        return result


    def protect_prompt(self, prompt: str) -> Dict:
        """
        Apply protection mechanisms to the prompt using advanced tools.
        """
        prompt = self._normalize(prompt)
        protected_prompt = prompt
        protections_applied = []
        canary = None

        # Add canary word if Rebuff is enabled
        if self.advanced_security.rebuff.enabled:
            protected_prompt, canary = self.advanced_security.rebuff.add_canary_word(prompt)
            protections_applied.append("Canary word injection protection")

        # Apply Guardrails filtering if enabled
        if self.advanced_security.guardrails.enabled:
            validation = self.advanced_security.guardrails.validate_prompt(prompt)
            if 'filtered_prompt' in validation:
                protected_prompt = validation['filtered_prompt']
                protections_applied.append("Guardrails content filtering")

        # Apply LMQL constraints if enabled
        if self.advanced_security.lmql.enabled:
            constraints = {
                'max_length': 2000,
                'forbidden_words': ['system', 'ignore', 'bypass', 'admin', 'jailbreak'],
                'temperature': 0.7
            }
            protected_prompt = self.advanced_security.lmql.create_constrained_query(
                protected_prompt, constraints
            )
            protections_applied.append("LMQL constraint enforcement")

        return {
            'original': prompt,
            'protected': protected_prompt,
            'protections': protections_applied,
            'canary': canary
        }

    def validate_response(self, response: str, context: Dict) -> Dict:
        """
        Validate LLM response for security issues.
        """
        issues = []

        # Normalize response
        response = self._normalize(response)

        # Check for canary leak
        if 'canary' in context and context['canary']:
            if self.advanced_security.rebuff.check_canary_leak(response, context['canary']):
                issues.append("System prompt leakage detected via canary word")

        # Check for injection patterns in response
        response_analysis = self.analyze_prompt(response)
        if response_analysis['injection_detected']:
            issues.append("Response contains potential injection patterns")

        # Check for SQL patterns in response
        sql_check = self.check_sql_injection(response)
        if sql_check['detected']:
            issues.append("Response contains SQL injection patterns")

        # Validate against LMQL constraints
        if 'constraints' in context and self.advanced_security.lmql.enabled:
            validation = self.advanced_security.lmql.validate_response(
                response, context['constraints']
            )
            if not validation['valid']:
                issues.extend(validation['violations'])

        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'risk_score': min(len(issues) * 25, 100)
        }

# For backward compatibility, keep the original class name
PromptAnalyzer = EnhancedPromptAnalyzer
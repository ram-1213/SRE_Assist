"""
Enhanced Code Security Analyzer with Advanced Threat Detection - UPDATED
"""
import subprocess
import tempfile
import json
import re
import ast
import hashlib
from typing import Dict, List, Tuple, Optional, Any
import os
import logging
import threading
import time
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import secrets

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    type: str
    severity: str
    line: int
    description: str
    recommendation: str
    cwe_id: Optional[str] = None
    confidence: float = 1.0
    code_snippet: str = ""

class EnhancedCodeAnalyzer:
    def __init__(self):
        self.vulnerability_patterns = {
            # SQL Injection patterns
            'sql_injection': {
                'patterns': [
                    r'f".*SELECT.*{[^}]+}.*"',
                    r'f".*INSERT.*{[^}]+}.*"',
                    r'f".*UPDATE.*{[^}]+}.*"',
                    r'f".*DELETE.*{[^}]+}.*"',
                    r'\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)',
                    r'%\s*%.*(?:SELECT|INSERT|UPDATE|DELETE)',
                    r'cursor\.execute\([^,]*%[^,]*\)',
                    r'execute\(["\'].*\+.*["\']',
                    r'query\s*=.*\+.*(?:SELECT|INSERT|UPDATE|DELETE)',
                    r'(?:SELECT|INSERT|UPDATE|DELETE).*\+.*user',
                ],
                'severity': 'critical',
                'cwe': 'CWE-89'
            },

            # ENHANCED Command Injection patterns
            'command_injection': {
                'patterns': [
                    r'os\.system\([^)]*\+',
                    r'os\.system\([^)]*%',
                    r'os\.system\([^)]*\.format',
                    r'subprocess\.call\([^)]*shell=True[^)]*\+',
                    r'subprocess\.run\([^)]*shell=True[^)]*\+',
                    r'subprocess\.Popen\([^)]*shell=True[^)]*\+',
                    r'os\.popen\([^)]*\+',
                    r'commands\.getoutput\([^)]*\+',
                    r'eval\(.*input\(',
                    r'exec\(.*input\(',
                    r'__import__\(.*input\(',
                    # NEW PATTERNS - These catch the Flask vulnerabilities
                    r'subprocess\.run\([^)]*command[^)]*\)',  # subprocess.run with command variable
                    r'subprocess\.call\([^)]*command[^)]*\)',  # subprocess.call with command variable
                    r'subprocess\.Popen\([^)]*command[^)]*\)', # subprocess.Popen with command variable
                    r'f\.read\(\).*subprocess',               # Reading file then executing with subprocess
                    r'file_content.*subprocess',              # File content used in subprocess
                    r'command\s*=\s*f\.read\(\)',            # Command variable from file read
                    r'with\s+open.*subprocess\.run',         # File read followed by subprocess execution
                    r'for.*files.*subprocess\.run',          # Loop through files executing subprocess
                ],
                'severity': 'critical',
                'cwe': 'CWE-78'
            },

            # ENHANCED Path Traversal patterns
            'path_traversal': {
                'patterns': [
                    r'\.\./\.\.',
                    r'\.\.\\\.\.',
                    r'os\.path\.join\([^)]*\.\.',
                    r'open\([^)]*\+[^)]*["\'][^"\']*\.\.',
                    r'pathlib.*joinpath\([^)]*\.\.',
                    r'file_path\s*=.*\+.*\.\.',
                    r'\.\.[\\/].*[\\/]\.\.',
                    # NEW PATTERNS - These catch ZIP extraction vulnerabilities
                    r'zip_ref\.extractall\([^)]*\)',         # Unsafe ZIP extraction
                    r'zipfile\..*extractall\([^)]*\)',       # Any zipfile extractall
                    r'\.extractall\([^)]*[^)]*\)',           # Generic extractall without validation
                    r'extract_dir.*extractall',              # Extract directory used unsafely
                ],
                'severity': 'high',
                'cwe': 'CWE-22'
            },

            # NEW - File Processing Vulnerabilities
            'unsafe_file_processing': {
                'patterns': [
                    r'for.*files.*open.*subprocess',         # Loop files, open, then subprocess
                    r'os\.walk.*subprocess\.run',            # Walk directory then execute subprocess
                    r'file_content.*exec\(',                 # Execute file contents
                    r'with\s+open.*exec\(',                  # Read file then exec
                    r'f\.read\(\).*exec\(',                  # File read then exec
                    r'\.read\(\).*os\.system',               # File read then os.system
                    r'for\s+.*\s+in\s+files.*command',      # Loop through files creating commands
                ],
                'severity': 'critical',
                'cwe': 'CWE-78'
            },

            # Cross-Site Scripting (XSS)
            'xss': {
                'patterns': [
                    r'innerHTML\s*=',
                    r'document\.write\(',
                    r'\.html\([^)]*user',
                    r'v-html\s*=',
                    r'dangerouslySetInnerHTML',
                    r'\.append\([^)]*<script',
                    r'response\.write\([^)]*[<>]',
                    r'print\([^)]*<script',
                ],
                'severity': 'high',
                'cwe': 'CWE-79'
            },

            # Hardcoded Credentials
            'hardcoded_secrets': {
                'patterns': [
                    r'api_key\s*=\s*["\'][\w]{20,}["\']',
                    r'password\s*=\s*["\'][^"\']{6,}["\']',
                    r'secret\s*=\s*["\'][^"\']{10,}["\']',
                    r'token\s*=\s*["\'][\w]{20,}["\']',
                    r'private_key\s*=\s*["\']',
                    r'aws_access_key\s*=\s*["\'][^"\']+["\']',
                    r'aws_secret\s*=\s*["\'][^"\']+["\']',
                    r'["\']sk-[a-zA-Z0-9]{48}["\']',  # OpenAI API key
                    r'["\']pk_[a-zA-Z0-9]{32}["\']',  # Publishable key
                    r'["\']rk_[a-zA-Z0-9]{32}["\']',  # Restricted key
                    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                    r'["\'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["\']',  # UUID
                ],
                'severity': 'high',
                'cwe': 'CWE-798'
            },

            # Insecure Randomness
            'insecure_random': {
                'patterns': [
                    r'random\.random\(',
                    r'random\.randint\(',
                    r'Math\.random\(',
                    r'random\.choice\(',
                    r'random\.randrange\(',
                    r'random\.uniform\(',
                    r'time\.time\(\)\s*%',
                ],
                'severity': 'medium',
                'cwe': 'CWE-338'
            },

            # Weak Cryptography
            'weak_crypto': {
                'patterns': [
                    r'hashlib\.md5\(',
                    r'hashlib\.sha1\(',
                    r'from Crypto\.Cipher import DES',
                    r'from Crypto\.Cipher import ARC4',
                    r'from Crypto\.Cipher import RC4',
                    r'DES\.new\(',
                    r'ARC4\.new\(',
                    r'MODE_ECB',
                    r'Blowfish\(',
                    r'MD5\(',
                ],
                'severity': 'medium',
                'cwe': 'CWE-327'
            },

            # Deserialization Attacks
            'insecure_deserialization': {
                'patterns': [
                    r'pickle\.loads\(',
                    r'pickle\.load\([^)]*\)',
                    r'yaml\.load\([^,)]*\)',  # without SafeLoader
                    r'eval\(.*json',
                    r'marshal\.loads\(',
                    r'shelve\.open\(',
                    r'dill\.loads\(',
                    r'jsonpickle\.decode\(',
                ],
                'severity': 'critical',
                'cwe': 'CWE-502'
            },

            # XML External Entity (XXE)
            'xxe_injection': {
                'patterns': [
                    r'etree\.parse\([^)]*\)',
                    r'etree\.fromstring\(',
                    r'minidom\.parseString\(',
                    r'pulldom\.parseString\(',
                    r'XMLParser\([^)]*resolve_entities=True',
                    r'xml\.etree\.ElementTree\.parse',
                    r'xml\.dom\.minidom\.parse',
                ],
                'severity': 'high',
                'cwe': 'CWE-611'
            },

            # LDAP Injection
            'ldap_injection': {
                'patterns': [
                    r'ldap\.search\([^)]*%',
                    r'ldap\.search\([^)]*\+',
                    r'ldap\.search\([^)]*format\(',
                    r'ldap\.search_s\([^)]*%',
                    r'ldap3\..*search\([^)]*\+',
                ],
                'severity': 'high',
                'cwe': 'CWE-90'
            },

            # File Upload Vulnerabilities
            'file_upload': {
                'patterns': [
                    r'move_uploaded_file\(',
                    r'\.save\([^)]*request\.files',
                    r'werkzeug.*secure_filename',
                    r'open\([^)]*[\'"]wb[\'"]\)',
                    r'with open\([^)]*user.*[\'"]w[b]?[\'"]\)',
                    r'shutil\.copy\([^)]*request',
                ],
                'severity': 'high',
                'cwe': 'CWE-434'
            },

            # Information Disclosure
            'info_disclosure': {
                'patterns': [
                    r'print\([^)]*password',
                    r'print\([^)]*secret',
                    r'print\([^)]*token',
                    r'logger\.[^(]*\([^)]*password',
                    r'console\.log\([^)]*password',
                    r'echo.*\$password',
                    r'traceback\.print_exc\(\)',
                ],
                'severity': 'medium',
                'cwe': 'CWE-200'
            }
        }

        # AI/ML specific vulnerabilities
        self.ai_ml_patterns = {
            'model_injection': {
                'patterns': [
                    r'model\.load_state_dict\([^)]*user',
                    r'torch\.load\([^)]*user',
                    r'joblib\.load\([^)]*user',
                    r'pickle\.load.*model',
                    r'tf\.saved_model\.load\([^)]*user',
                ],
                'severity': 'critical',
                'cwe': 'CWE-502'
            },
            'prompt_injection': {
                'patterns': [
                    r'f".*{.*}.*ignore.*instructions',
                    r'prompt\s*\+\s*user_input',
                    r'system.*user.*input.*without.*validation',
                    r'\.format\(.*user.*\).*system',
                ],
                'severity': 'high',
                'cwe': 'CWE-74'
            }
        }

    def analyze_code_comprehensive(self, code: str, language: str = 'python') -> Dict[str, Any]:
        """Comprehensive code analysis with multiple detection methods"""
        start_time = time.time()

        results = {
            'vulnerabilities': [],
            'risk_score': 0,
            'analysis_time': 0,
            'code_quality': {},
            'security_metrics': {},
            'recommendations': [],
            'code_complexity': self._calculate_complexity(code),
            'language': language
        }

        try:
            # Pattern-based analysis
            pattern_vulns = self._pattern_analysis(code)
            results['vulnerabilities'].extend(pattern_vulns)

            # AST-based analysis for Python
            if language == 'python':
                ast_vulns = self._ast_analysis(code)
                results['vulnerabilities'].extend(ast_vulns)

            # AI/ML specific analysis
            ai_vulns = self._ai_ml_analysis(code)
            results['vulnerabilities'].extend(ai_vulns)

            # Crypto analysis
            crypto_vulns = self._crypto_analysis(code)
            results['vulnerabilities'].extend(crypto_vulns)

            # Calculate risk metrics
            results.update(self._calculate_risk_metrics(results['vulnerabilities']))

            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(results['vulnerabilities'])

            # Remove duplicates
            results['vulnerabilities'] = self._deduplicate_vulnerabilities(results['vulnerabilities'])

        except Exception as e:
            logger.error(f"Code analysis error: {e}")
            results['error'] = str(e)

        results['analysis_time'] = time.time() - start_time
        return results

    def _pattern_analysis(self, code: str) -> List[Vulnerability]:
        """Enhanced pattern-based vulnerability detection"""
        vulnerabilities = []
        lines = code.split('\n')

        # Combine all patterns
        all_patterns = {**self.vulnerability_patterns, **self.ai_ml_patterns}

        for vuln_type, config in all_patterns.items():
            for pattern in config['patterns']:
                try:
                    matches = list(re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE))
                    for match in matches:
                        line_num = code[:match.start()].count('\n') + 1

                        # Get context
                        start_line = max(0, line_num - 2)
                        end_line = min(len(lines), line_num + 2)
                        context = '\n'.join(lines[start_line:end_line])

                        vuln = Vulnerability(
                            type=vuln_type,
                            severity=config['severity'],
                            line=line_num,
                            description=f"{vuln_type.replace('_', ' ').title()} detected",
                            recommendation=self._get_recommendation(vuln_type),
                            cwe_id=config.get('cwe'),
                            confidence=0.8,
                            code_snippet=context[:200]
                        )
                        vulnerabilities.append(vuln)

                except re.error as e:
                    logger.debug(f"Regex error in pattern {pattern}: {e}")
                    continue

        return vulnerabilities

    def _ast_analysis(self, code: str) -> List[Vulnerability]:
        """AST-based analysis for deeper Python code inspection"""
        vulnerabilities = []

        try:
            tree = ast.parse(code)

            class VulnerabilityVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.vulns = []

                def visit_Call(self, node):
                    # Check for dangerous function calls
                    if isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name):
                            # os.system calls
                            if (node.func.value.id == 'os' and
                                node.func.attr == 'system'):
                                self.vulns.append(Vulnerability(
                                    type='command_execution',
                                    severity='critical',
                                    line=node.lineno,
                                    description='Direct OS command execution detected',
                                    recommendation='Use subprocess with proper argument validation',
                                    cwe_id='CWE-78',
                                    confidence=0.9
                                ))

                            # subprocess.run/call/Popen calls
                            elif (node.func.value.id == 'subprocess' and
                                  node.func.attr in ['run', 'call', 'Popen']):
                                # Check if command comes from variable (more dangerous)
                                if node.args and isinstance(node.args[0], ast.Name):
                                    self.vulns.append(Vulnerability(
                                        type='command_injection',
                                        severity='critical',
                                        line=node.lineno,
                                        description=f'subprocess.{node.func.attr}() with variable command detected',
                                        recommendation='Never execute file contents as commands. Use allowlists and validation.',
                                        cwe_id='CWE-78',
                                        confidence=0.95
                                    ))

                    elif isinstance(node.func, ast.Name):
                        # eval() calls
                        if node.func.id in ['eval', 'exec']:
                            self.vulns.append(Vulnerability(
                                type='code_injection',
                                severity='critical',
                                line=node.lineno,
                                description=f'{node.func.id}() call detected',
                                recommendation=f'Avoid {node.func.id}() with user input',
                                cwe_id='CWE-94',
                                confidence=0.9
                            ))

                    self.generic_visit(node)

                def visit_Import(self, node):
                    # Check for dangerous imports
                    for alias in node.names:
                        if alias.name in ['pickle', 'marshal', 'dill']:
                            self.vulns.append(Vulnerability(
                                type='dangerous_import',
                                severity='medium',
                                line=node.lineno,
                                description=f'Import of {alias.name} (deserialization risk)',
                                recommendation='Use safe serialization alternatives like JSON',
                                cwe_id='CWE-502',
                                confidence=0.6
                            ))

                    self.generic_visit(node)

            visitor = VulnerabilityVisitor()
            visitor.visit(tree)
            vulnerabilities.extend(visitor.vulns)

        except SyntaxError:
            # Code might not be valid Python, skip AST analysis
            pass
        except Exception as e:
            logger.debug(f"AST analysis error: {e}")

        return vulnerabilities

    def _ai_ml_analysis(self, code: str) -> List[Vulnerability]:
        """Specialized analysis for AI/ML security issues"""
        vulnerabilities = []

        # Check for model security issues
        ai_patterns = [
            (r'model\.load\([^)]*user', 'Untrusted model loading', 'critical'),
            (r'torch\.load\([^)]*(?!map_location)', 'Unsafe PyTorch model loading', 'high'),
            (r'joblib\.load\([^)]*user', 'Unsafe joblib deserialization', 'high'),
            (r'prompt\s*=.*\+.*user', 'Prompt injection risk', 'high'),
            (r'openai\..*\([^)]*user.*\)', 'Unvalidated API input', 'medium'),
        ]

        for pattern, desc, severity in ai_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                vulnerabilities.append(Vulnerability(
                    type='ai_ml_security',
                    severity=severity,
                    line=line_num,
                    description=desc,
                    recommendation='Validate and sanitize all AI model inputs',
                    confidence=0.7
                ))

        return vulnerabilities

    def _crypto_analysis(self, code: str) -> List[Vulnerability]:
        """Cryptographic security analysis"""
        vulnerabilities = []

        crypto_issues = [
            (r'AES\.new\([^,)]*[,\s]*AES\.MODE_ECB', 'ECB mode is insecure', 'high'),
            (r'random\.randint.*(?:key|password|token)', 'Weak random for crypto', 'high'),
            (r'time\.time\(\).*(?:seed|key)', 'Predictable seed/key', 'high'),
            (r'hashlib\.md5\([^)]*password', 'MD5 for password hashing', 'high'),
            (r'base64\.encode.*(?:password|secret)', 'Base64 is not encryption', 'medium'),
        ]

        for pattern, desc, severity in crypto_issues:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                vulnerabilities.append(Vulnerability(
                    type='cryptographic_weakness',
                    severity=severity,
                    line=line_num,
                    description=desc,
                    recommendation='Use cryptographically secure implementations',
                    cwe_id='CWE-327',
                    confidence=0.8
                ))

        return vulnerabilities

    def _calculate_complexity(self, code: str) -> Dict[str, int]:
        """Calculate code complexity metrics"""
        lines = code.split('\n')

        return {
            'total_lines': len(lines),
            'code_lines': len([l for l in lines if l.strip() and not l.strip().startswith('#')]),
            'comment_lines': len([l for l in lines if l.strip().startswith('#')]),
            'cyclomatic_complexity': self._cyclomatic_complexity(code),
            'function_count': len(re.findall(r'def\s+\w+', code)),
            'class_count': len(re.findall(r'class\s+\w+', code))
        }

    def _cyclomatic_complexity(self, code: str) -> int:
        """Calculate cyclomatic complexity"""
        # Simple approximation based on control flow keywords
        complexity_keywords = ['if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally', 'with']
        complexity = 1  # Base complexity

        for keyword in complexity_keywords:
            complexity += len(re.findall(rf'\b{keyword}\b', code))

        return complexity

    def _calculate_risk_metrics(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Calculate overall risk metrics"""
        if not vulnerabilities:
            return {
                'risk_score': 0,
                'security_metrics': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }

        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2}
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        total_score = 0
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
            total_score += severity_weights[vuln.severity] * vuln.confidence

        # Normalize score to 0-100 range
        max_possible_score = len(vulnerabilities) * 10
        risk_score = min(100, (total_score / max_possible_score * 100) if max_possible_score > 0 else 0)

        return {
            'risk_score': risk_score,
            'security_metrics': severity_counts
        }

    def _generate_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        vuln_types = set(v.type for v in vulnerabilities)

        recommendation_map = {
            'sql_injection': 'Use parameterized queries and prepared statements',
            'command_injection': 'NEVER execute file contents as commands. Use allowlists and validation.',
            'unsafe_file_processing': 'Validate all file operations and never execute file contents',
            'xss': 'Encode output and implement Content Security Policy',
            'hardcoded_secrets': 'Use environment variables or secure key management',
            'insecure_deserialization': 'Use safe serialization formats like JSON',
            'weak_crypto': 'Use modern cryptographic algorithms (AES-256, SHA-256+)',
            'path_traversal': 'Validate and sanitize file paths, use secure extraction methods',
            'ai_ml_security': 'Implement input validation and model security controls'
        }

        for vuln_type in vuln_types:
            if vuln_type in recommendation_map:
                recommendations.append(recommendation_map[vuln_type])

        # General recommendations based on severity
        critical_count = len([v for v in vulnerabilities if v.severity == 'critical'])
        if critical_count > 0:
            recommendations.insert(0, f'{critical_count} critical vulnerabilities require immediate attention')

        return recommendations[:5]  # Limit to top 5 recommendations

    def _get_recommendation(self, vuln_type: str) -> str:
        """Get specific recommendation for vulnerability type"""
        recommendations = {
            'sql_injection': 'Use parameterized queries instead of string concatenation',
            'command_injection': 'NEVER execute file contents as commands. Use allowlists and proper validation.',
            'unsafe_file_processing': 'Do not execute file contents. Validate all file operations.',
            'path_traversal': 'Validate file paths and use secure extraction methods with path validation',
            'xss': 'Encode all user output and implement CSP headers',
            'hardcoded_secrets': 'Use environment variables or secure vaults',
            'insecure_random': 'Use secrets module for cryptographic randomness',
            'weak_crypto': 'Use SHA-256 or stronger hash functions',
            'insecure_deserialization': 'Use JSON instead of pickle for data serialization',
            'xxe_injection': 'Use defusedxml library or disable entity processing',
            'ldap_injection': 'Escape special characters in LDAP queries',
            'file_upload': 'Validate file types and store outside web root',
            'info_disclosure': 'Remove sensitive data from logs and error messages',
            'ai_ml_security': 'Validate and sanitize all AI model inputs and outputs'
        }

        return recommendations.get(vuln_type, 'Follow secure coding best practices')

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique_vulns = []

        for vuln in vulnerabilities:
            # Create unique key based on type, line, and partial description
            key = (vuln.type, vuln.line, vuln.description[:50])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        # Sort by severity and line number
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        unique_vulns.sort(key=lambda v: (severity_order[v.severity], v.line))

        return unique_vulns

    def generate_security_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate a formatted security report"""
        report = []
        report.append("=== SECURITY ANALYSIS REPORT ===\n")

        # Summary
        risk_score = analysis_results.get('risk_score', 0)
        vuln_count = len(analysis_results.get('vulnerabilities', []))

        report.append(f"Risk Score: {risk_score:.1f}/100")
        report.append(f"Vulnerabilities Found: {vuln_count}")
        report.append(f"Analysis Time: {analysis_results.get('analysis_time', 0):.2f}s\n")

        # Severity breakdown
        metrics = analysis_results.get('security_metrics', {})
        if metrics:
            report.append("Severity Breakdown:")
            for severity, count in metrics.items():
                if count > 0:
                    report.append(f"  {severity.upper()}: {count}")
            report.append("")

        # Top vulnerabilities
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        if vulnerabilities:
            report.append("Top Vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                report.append(f"{i}. {vuln.description}")
                report.append(f"   Line {vuln.line} | {vuln.severity.upper()} | {vuln.cwe_id or 'N/A'}")
                report.append(f"   Recommendation: {vuln.recommendation}")
                report.append("")

        # Recommendations
        recommendations = analysis_results.get('recommendations', [])
        if recommendations:
            report.append("Security Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                report.append(f"{i}. {rec}")

        return '\n'.join(report)

# Legacy compatibility
class CodeAnalyzer(EnhancedCodeAnalyzer):
    """Legacy wrapper for backward compatibility"""
    def analyze_code(self, code: str) -> Dict:
        """Legacy method wrapper"""
        results = self.analyze_code_comprehensive(code)

        # Convert to legacy format
        legacy_vulns = []
        for vuln in results['vulnerabilities']:
            legacy_vulns.append({
                'type': vuln.type,
                'severity': vuln.severity,
                'line': vuln.line,
                'recommendation': vuln.recommendation,
                'tool': 'enhanced_analyzer',
                'confidence': vuln.confidence,
                'code_snippet': vuln.code_snippet
            })

        return {
            'vulnerabilities': legacy_vulns,
            'risk_level': 'high' if results['risk_score'] > 70 else 'medium' if results['risk_score'] > 30 else 'low',
            'details': [v.description for v in results['vulnerabilities']],
            'tools_used': ['pattern_analysis', 'ast_analysis', 'ai_ml_analysis']
        }
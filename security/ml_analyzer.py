"""
Enhanced ML-based code analysis with working implementations
"""
import re
import ast
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class MLAnalyzer:
    def __init__(self):
        # Comprehensive security keyword analysis
        self.security_keywords = {
            # High risk keywords (weight: 25-35)
            'critical': [
                ('eval', 35), ('exec', 35), ('__import__', 30), ('compile', 30),
                ('os.system', 35), ('subprocess.call', 30), ('subprocess.run', 30),
                ('pickle.loads', 35), ('marshal.loads', 30), ('yaml.unsafe_load', 35),
                ('shell=True', 30), ('input()', 25), ('raw_input()', 25)
            ],
            # Medium risk keywords (weight: 15-25)
            'medium': [
                ('open(', 20), ('file(', 20), ('globals()', 20), ('locals()', 20),
                ('vars()', 15), ('dir()', 15), ('getattr', 20), ('setattr', 20),
                ('delattr', 20), ('hasattr', 15), ('reload', 25), ('execfile', 25)
            ],
            # Low risk keywords (weight: 5-15)
            'low': [
                ('urllib', 10), ('requests', 10), ('socket', 15), ('threading', 10),
                ('multiprocessing', 10), ('tempfile', 10), ('shutil', 10),
                ('pathlib', 5), ('json.loads', 5), ('base64', 5)
            ]
        }

        # Vulnerability patterns with context
        self.vulnerability_patterns = {
            'sql_injection': [
                (r'f".*SELECT.*{[^}]+}.*"', 30),
                (r'f".*INSERT.*{[^}]+}.*"', 30),
                (r'f".*UPDATE.*{[^}]+}.*"', 30),
                (r'f".*DELETE.*{[^}]+}.*"', 30),
                (r'\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)', 25),
                (r'cursor\.execute\([^,]*%[^,]*\)', 25),
                (r'execute\(["\'].*\+.*["\']', 25)
            ],
            'command_injection': [
                (r'os\.system\([^)]*\+', 35),
                (r'subprocess\..*shell=True.*\+', 30),
                (r'os\.popen\([^)]*\+', 25),
                (r'commands\.getoutput\([^)]*\+', 25)
            ],
            'deserialization': [
                (r'pickle\.loads\([^)]*\)', 35),
                (r'marshal\.loads\([^)]*\)', 30),
                (r'yaml\.load\([^,)]*\)', 25),
                (r'dill\.loads\([^)]*\)', 30)
            ],
            'code_injection': [
                (r'eval\([^)]*input', 40),
                (r'exec\([^)]*input', 40),
                (r'compile\([^)]*input', 35)
            ]
        }

        # Code complexity indicators
        self.complexity_indicators = {
            'nested_loops': r'for.*for.*:',
            'nested_conditions': r'if.*if.*:',
            'exception_handling': r'try:.*except',
            'lambda_functions': r'lambda\s+[^:]+:',
            'list_comprehensions': r'\[.*for.*in.*\]',
            'recursive_calls': r'def\s+(\w+).*\1\('
        }

    def analyze_code_with_models(self, code: str) -> Dict:
        """Comprehensive code analysis using multiple techniques"""
        results = {
            'keyword_score': 0,
            'pattern_score': 0,
            'complexity_score': 0,
            'ast_score': 0,
            'overall_risk': 0,
            'ml_risk_level': 'low',
            'ml_recommendations': [],
            'vulnerability_details': {},
            'code_metrics': {}
        }

        try:
            # 1. Keyword-based analysis
            keyword_result = self._enhanced_keyword_analysis(code)
            results.update(keyword_result)

            # 2. Pattern-based vulnerability detection
            pattern_result = self._pattern_vulnerability_analysis(code)
            results['pattern_score'] = pattern_result['score']
            results['vulnerability_details'] = pattern_result['vulnerabilities']

            # 3. Code complexity analysis
            complexity_result = self._complexity_analysis(code)
            results['complexity_score'] = complexity_result['score']
            results['code_metrics'] = complexity_result['metrics']

            # 4. AST-based analysis (if possible)
            ast_result = self._ast_security_analysis(code)
            results['ast_score'] = ast_result['score']

            # 5. Calculate overall risk
            overall_risk = self._calculate_overall_risk(results)
            results['overall_risk'] = overall_risk

            # 6. Determine risk level and recommendations
            results.update(self._determine_risk_level_and_recommendations(results))

            # For backward compatibility
            results['codebert_score'] = overall_risk
            results['codet5_score'] = pattern_result['score']

        except Exception as e:
            logger.error(f"ML analysis error: {e}")
            results['overall_risk'] = 50
            results['ml_risk_level'] = 'unknown'

        return results

    def _enhanced_keyword_analysis(self, code: str) -> Dict:
        """Enhanced keyword analysis with context awareness"""
        code_lower = code.lower()
        total_score = 0
        detected_keywords = []

        # Analyze each category
        for category, keywords in self.security_keywords.items():
            for keyword, weight in keywords:
                if keyword.lower() in code_lower:
                    # Check context for keyword
                    context_multiplier = self._analyze_keyword_context(code, keyword)
                    adjusted_weight = weight * context_multiplier
                    total_score += adjusted_weight
                    detected_keywords.append({
                        'keyword': keyword,
                        'category': category,
                        'weight': adjusted_weight,
                        'context': 'dangerous' if context_multiplier > 1 else 'safe'
                    })

        return {
            'keyword_score': min(total_score, 100),
            'detected_keywords': detected_keywords
        }

    def _analyze_keyword_context(self, code: str, keyword: str) -> float:
        """Analyze the context around dangerous keywords"""
        lines = code.split('\n')
        multiplier = 1.0

        for line in lines:
            if keyword.lower() in line.lower():
                line = line.strip().lower()

                # Higher risk if keyword is used with user input
                if any(term in line for term in ['input', 'argv', 'request', 'form', 'user']):
                    multiplier = 1.5

                # Lower risk if in comments
                elif line.startswith('#') or line.startswith('//'):
                    multiplier = 0.3

                # Higher risk if in try-except (might be hiding something)
                elif 'except' in line or 'try:' in line:
                    multiplier = 1.2

                # Lower risk if clearly for legitimate purposes
                elif any(term in line for term in ['test', 'example', 'demo', 'safe']):
                    multiplier = 0.7

        return multiplier

    def _pattern_vulnerability_analysis(self, code: str) -> Dict:
        """Analyze code for specific vulnerability patterns"""
        vulnerabilities = {}
        total_score = 0

        for vuln_type, patterns in self.vulnerability_patterns.items():
            vuln_score = 0
            matches = []

            for pattern, weight in patterns:
                matches_found = re.findall(pattern, code, re.IGNORECASE)
                if matches_found:
                    vuln_score += weight
                    matches.extend(matches_found)

            if matches:
                vulnerabilities[vuln_type] = {
                    'score': min(vuln_score, 100),
                    'matches': len(matches),
                    'examples': matches[:3]  # Show first 3 examples
                }
                total_score += vuln_score

        return {
            'score': min(total_score, 100),
            'vulnerabilities': vulnerabilities
        }

    def _complexity_analysis(self, code: str) -> Dict:
        """Analyze code complexity which can indicate potential issues"""
        metrics = {
            'lines_of_code': len([l for l in code.split('\n') if l.strip()]),
            'cyclomatic_complexity': 1,  # Base complexity
            'nesting_depth': 0,
            'function_count': 0,
            'class_count': 0
        }

        complexity_score = 0

        # Count basic metrics
        metrics['function_count'] = len(re.findall(r'def\s+\w+', code))
        metrics['class_count'] = len(re.findall(r'class\s+\w+', code))

        # Calculate cyclomatic complexity (simplified)
        complexity_keywords = ['if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally']
        for keyword in complexity_keywords:
            metrics['cyclomatic_complexity'] += len(re.findall(rf'\b{keyword}\b', code))

        # Estimate nesting depth
        max_nesting = 0
        current_nesting = 0
        for line in code.split('\n'):
            stripped = line.lstrip()
            if stripped:
                indent_level = (len(line) - len(stripped)) // 4  # Assuming 4-space indents
                max_nesting = max(max_nesting, indent_level)

        metrics['nesting_depth'] = max_nesting

        # Calculate complexity score
        if metrics['cyclomatic_complexity'] > 20:
            complexity_score += 30
        elif metrics['cyclomatic_complexity'] > 10:
            complexity_score += 15

        if metrics['nesting_depth'] > 5:
            complexity_score += 25
        elif metrics['nesting_depth'] > 3:
            complexity_score += 10

        if metrics['lines_of_code'] > 500:
            complexity_score += 20
        elif metrics['lines_of_code'] > 200:
            complexity_score += 10

        return {
            'score': min(complexity_score, 100),
            'metrics': metrics
        }

    def _ast_security_analysis(self, code: str) -> Dict:
        """AST-based security analysis"""
        try:
            tree = ast.parse(code)
            security_issues = []

            class SecurityVisitor(ast.NodeVisitor):
                def visit_Call(self, node):
                    # Check for dangerous function calls
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec', 'compile']:
                            security_issues.append(f"Dangerous function: {node.func.id}")
                    elif isinstance(node.func, ast.Attribute):
                        if hasattr(node.func, 'attr') and node.func.attr in ['system', 'popen']:
                            security_issues.append(f"System call: {node.func.attr}")
                    self.generic_visit(node)

                def visit_Import(self, node):
                    for alias in node.names:
                        if alias.name in ['os', 'subprocess', 'pickle', 'marshal']:
                            security_issues.append(f"Potentially dangerous import: {alias.name}")
                    self.generic_visit(node)

            visitor = SecurityVisitor()
            visitor.visit(tree)

            return {'score': min(len(security_issues) * 20, 100), 'issues': security_issues}

        except SyntaxError:
            return {'score': 10, 'issues': ['Code has syntax errors']}
        except Exception as e:
            return {'score': 0, 'issues': []}

    def _calculate_overall_risk(self, results: Dict) -> float:
        """Calculate overall risk score from all analyses"""
        weights = {
            'keyword_score': 0.3,
            'pattern_score': 0.4,
            'complexity_score': 0.2,
            'ast_score': 0.1
        }

        total_score = 0
        for metric, weight in weights.items():
            total_score += results.get(metric, 0) * weight

        return min(total_score, 100)

    def _determine_risk_level_and_recommendations(self, results: Dict) -> Dict:
        """Determine risk level and generate recommendations"""
        overall_risk = results['overall_risk']

        if overall_risk > 70:
            risk_level = 'high'
            recommendations = [
                'Code contains high-risk patterns that require immediate review',
                'Consider refactoring to remove dangerous function calls',
                'Implement input validation and sanitization',
                'Review all external dependencies and imports'
            ]
        elif overall_risk > 40:
            risk_level = 'medium'
            recommendations = [
                'Code has some security concerns that should be addressed',
                'Review usage of potentially dangerous functions',
                'Consider adding error handling and input validation',
                'Test code thoroughly in a secure environment'
            ]
        else:
            risk_level = 'low'
            recommendations = [
                'Code appears to follow secure coding practices',
                'Continue following security best practices',
                'Regular security reviews are still recommended'
            ]

        # Add specific recommendations based on detected issues
        if results.get('vulnerability_details'):
            for vuln_type, details in results['vulnerability_details'].items():
                if vuln_type == 'sql_injection':
                    recommendations.append('Use parameterized queries to prevent SQL injection')
                elif vuln_type == 'command_injection':
                    recommendations.append('Avoid shell=True and validate all system inputs')
                elif vuln_type == 'deserialization':
                    recommendations.append('Use safe serialization formats like JSON instead of pickle')
                elif vuln_type == 'code_injection':
                    recommendations.append('Never use eval/exec with user input')

        return {
            'ml_risk_level': risk_level,
            'ml_recommendations': recommendations[:5]  # Limit to top 5
        }

    def get_vulnerability_report(self, code: str) -> str:
        """Generate a detailed vulnerability report"""
        results = self.analyze_code_with_models(code)

        report = []
        report.append("=== ML SECURITY ANALYSIS REPORT ===\n")

        # Summary
        report.append(f"Overall Risk Score: {results['overall_risk']:.1f}/100")
        report.append(f"Risk Level: {results['ml_risk_level'].upper()}\n")

        # Detailed breakdown
        report.append("Analysis Breakdown:")
        report.append(f"  Keyword Analysis: {results['keyword_score']:.1f}/100")
        report.append(f"  Pattern Analysis: {results['pattern_score']:.1f}/100")
        report.append(f"  Complexity Analysis: {results['complexity_score']:.1f}/100")
        report.append(f"  AST Analysis: {results['ast_score']:.1f}/100\n")

        # Vulnerabilities found
        if results['vulnerability_details']:
            report.append("Vulnerabilities Detected:")
            for vuln_type, details in results['vulnerability_details'].items():
                report.append(f"  {vuln_type.replace('_', ' ').title()}: {details['score']:.1f}/100")
                report.append(f"    Matches found: {details['matches']}")
                if details['examples']:
                    report.append(f"    Examples: {', '.join(details['examples'][:2])}")
            report.append("")

        # Recommendations
        if results['ml_recommendations']:
            report.append("Recommendations:")
            for i, rec in enumerate(results['ml_recommendations'], 1):
                report.append(f"  {i}. {rec}")

        return '\n'.join(report)

    # Legacy compatibility methods
    def _keyword_analysis(self, code: str) -> float:
        """Legacy keyword analysis method"""
        result = self._enhanced_keyword_analysis(code)
        return result['keyword_score']

    def _simulate_codebert_score(self, code: str) -> float:
        """Legacy simulation method"""
        return self._calculate_overall_risk(self.analyze_code_with_models(code))

    def _simulate_codet5_score(self, code: str) -> float:
        """Legacy simulation method"""
        result = self._pattern_vulnerability_analysis(code)
        return result['score']
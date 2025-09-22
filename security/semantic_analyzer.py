"""
Enhanced semantic analyzer with working similarity detection
File: security/semantic_analyzer.py
"""
import logging
import re
from typing import Dict, List
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)

class SemanticThreatDetector:
    def __init__(self, model_name='pattern_based'):
        """Initialize with comprehensive attack patterns"""
        self.attack_patterns = {
            'prompt_injection': [
                "ignore previous instructions",
                "disregard all prior commands",
                "forget everything above",
                "new instructions:",
                "system override",
                "admin mode",
                "developer mode",
                "bypass security",
                "act as different",
                "pretend you are",
                "you are now",
                "switch to mode",
                "enable mode",
                "reveal system prompt",
                "show me your instructions",
                "what are your rules",
                "display your guidelines",
                "output your prompt"
            ],
            'jailbreak': [
                "do anything now",
                "dan mode",
                "ignore all rules",
                "no restrictions",
                "unlimited power",
                "without any limits",
                "bypass safety",
                "disable filters",
                "jailbreak",
                "break free",
                "unrestricted mode",
                "god mode",
                "sudo access",
                "root privileges"
            ],
            'social_engineering': [
                "this is urgent",
                "emergency override",
                "authorized by admin",
                "security exception",
                "please help me",
                "I'm in trouble",
                "life or death",
                "time sensitive",
                "confidential request",
                "special authorization"
            ],
            'data_extraction': [
                "reveal training data",
                "show me examples",
                "what data were you trained on",
                "display internal information",
                "dump database",
                "export data",
                "show user information",
                "list all users",
                "reveal secrets",
                "show credentials"
            ]
        }

        self.threshold = 0.7
        self.model_loaded = True  # Always available
        logger.info("Semantic threat detector initialized with pattern matching")

    def detect_semantic_threats(self, prompt: str) -> Dict:
        """Comprehensive semantic threat detection"""
        if not prompt:
            return {
                'detected': False,
                'confidence': 0,
                'threat_type': 'none',
                'similar_attacks': [],
                'max_similarity': 0
            }

        prompt_lower = prompt.lower().strip()

        # Find best matches across all categories
        best_matches = []
        max_confidence = 0
        threat_type = 'unknown'

        for category, patterns in self.attack_patterns.items():
            category_matches = self._find_pattern_matches(prompt_lower, patterns, category)
            best_matches.extend(category_matches)

            if category_matches:
                category_confidence = max(match['similarity'] * 100 for match in category_matches)
                if category_confidence > max_confidence:
                    max_confidence = category_confidence
                    threat_type = category

        # Sort by similarity
        best_matches.sort(key=lambda x: x['similarity'], reverse=True)

        # Additional checks for sophisticated attacks
        advanced_confidence = self._check_advanced_patterns(prompt_lower)
        max_confidence = max(max_confidence, advanced_confidence)

        return {
            'detected': max_confidence > 50,
            'confidence': max_confidence,
            'max_similarity': max_confidence / 100,
            'similar_attacks': best_matches[:5],
            'threat_type': threat_type if max_confidence > 50 else 'none',
            'method': 'semantic_pattern_matching',
            'advanced_patterns': advanced_confidence > 0
        }

    def _find_pattern_matches(self, prompt: str, patterns: List[str], category: str) -> List[Dict]:
        """Find matching patterns with similarity scoring"""
        matches = []

        for pattern in patterns:
            # Exact substring match
            if pattern in prompt:
                similarity = 0.95
                matches.append({
                    'pattern': pattern,
                    'similarity': similarity,
                    'match_type': 'exact',
                    'category': category
                })
                continue

            # Fuzzy matching using SequenceMatcher
            similarity = SequenceMatcher(None, pattern, prompt).ratio()
            if similarity > 0.6:
                matches.append({
                    'pattern': pattern,
                    'similarity': similarity,
                    'match_type': 'fuzzy',
                    'category': category
                })
                continue

            # Word-level matching
            pattern_words = set(pattern.split())
            prompt_words = set(prompt.split())

            # Check if most pattern words are present
            common_words = pattern_words.intersection(prompt_words)
            if len(common_words) >= len(pattern_words) * 0.7:
                word_similarity = len(common_words) / len(pattern_words)
                matches.append({
                    'pattern': pattern,
                    'similarity': word_similarity * 0.8,  # Slight penalty for word-level
                    'match_type': 'word_level',
                    'category': category
                })

        return matches

    def _check_advanced_patterns(self, prompt: str) -> float:
        """Check for sophisticated attack patterns"""
        confidence = 0

        # Check for instruction format patterns
        instruction_patterns = [
            r'step\s*\d+:',
            r'instruction\s*\d+:',
            r'rule\s*\d+:',
            r'command\s*\d+:',
            r'override\s+step\s*\d+',
            r'new\s+rule:',
            r'system\s*:',
            r'user\s*:',
            r'assistant\s*:'
        ]

        for pattern in instruction_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                confidence += 15

        # Check for encoding/obfuscation attempts
        encoding_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
            r'base64\s*:',
            r'rot13\s*:',
            r'decode\s+this',
            r'encrypted\s+message'
        ]

        for pattern in encoding_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                confidence += 20

        # Check for role-playing patterns
        roleplay_patterns = [
            r'you\s+are\s+now\s+',
            r'act\s+as\s+',
            r'pretend\s+to\s+be\s+',
            r'roleplay\s+as\s+',
            r'simulate\s+being\s+',
            r'imagine\s+you\s+are\s+'
        ]

        for pattern in roleplay_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                confidence += 10

        # Check for system prompt fishing
        system_patterns = [
            r'show\s+me\s+your\s+',
            r'reveal\s+your\s+',
            r'what\s+is\s+your\s+',
            r'tell\s+me\s+about\s+your\s+',
            r'describe\s+your\s+'
        ]

        system_targets = ['prompt', 'instructions', 'rules', 'guidelines', 'system', 'training']

        for sys_pattern in system_patterns:
            for target in system_targets:
                combined_pattern = sys_pattern + target
                if re.search(combined_pattern, prompt, re.IGNORECASE):
                    confidence += 25

        # Check for urgency/authority claims
        authority_patterns = [
            r'this\s+is\s+urgent',
            r'emergency\s+',
            r'authorized\s+by\s+',
            r'admin\s+override',
            r'security\s+exception',
            r'official\s+request',
            r'escalated\s+priority'
        ]

        for pattern in authority_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                confidence += 20

        return min(confidence, 100)

    def learn_from_feedback(self, prompt: str, is_malicious: bool, threat_type: str = None):
        """Learn from user feedback to improve detection"""
        if not prompt:
            return

        prompt_clean = prompt.lower().strip()

        if is_malicious and len(prompt_clean) < 200:  # Don't store very long prompts
            # Add to appropriate category or create new pattern
            if threat_type and threat_type in self.attack_patterns:
                # Check if similar pattern already exists
                existing_patterns = self.attack_patterns[threat_type]

                # Only add if not too similar to existing patterns
                is_novel = True
                for existing in existing_patterns:
                    similarity = SequenceMatcher(None, prompt_clean, existing).ratio()
                    if similarity > 0.8:
                        is_novel = False
                        break

                if is_novel:
                    self.attack_patterns[threat_type].append(prompt_clean[:100])
                    logger.info(f"Added new {threat_type} pattern from feedback")
            else:
                # Add to general prompt_injection category
                if 'prompt_injection' not in self.attack_patterns:
                    self.attack_patterns['prompt_injection'] = []

                self.attack_patterns['prompt_injection'].append(prompt_clean[:100])
                logger.info("Added new attack pattern from feedback")

    def cluster_attack_patterns(self) -> Dict:
        """Group similar attack patterns for analysis"""
        clusters = {}

        for category, patterns in self.attack_patterns.items():
            # Simple clustering by keyword similarity
            clustered = {}

            for pattern in patterns:
                # Find dominant keywords (ignore common words)
                words = [w for w in pattern.split() if len(w) > 3]
                if not words:
                    continue

                # Use first significant word as cluster key
                cluster_key = words[0] if words else 'misc'

                if cluster_key not in clustered:
                    clustered[cluster_key] = []
                clustered[cluster_key].append(pattern)

            clusters[category] = clustered

        return clusters

    def get_statistics(self) -> Dict:
        """Get detector statistics"""
        total_patterns = sum(len(patterns) for patterns in self.attack_patterns.values())

        return {
            'total_attack_patterns': total_patterns,
            'categories': len(self.attack_patterns),
            'patterns_by_category': {k: len(v) for k, v in self.attack_patterns.items()},
            'model_loaded': self.model_loaded,
            'threshold': self.threshold,
            'method': 'semantic_pattern_matching'
        }

    def analyze_attack_trends(self, recent_prompts: List[str]) -> Dict:
        """Analyze trends in recent attack attempts"""
        if not recent_prompts:
            return {'trends': [], 'most_common_category': None}

        category_counts = {category: 0 for category in self.attack_patterns.keys()}

        for prompt in recent_prompts:
            result = self.detect_semantic_threats(prompt)
            if result['detected']:
                threat_type = result['threat_type']
                if threat_type in category_counts:
                    category_counts[threat_type] += 1

        # Find most common attack type
        most_common = max(category_counts.items(), key=lambda x: x[1])

        trends = []
        for category, count in category_counts.items():
            if count > 0:
                trends.append({
                    'category': category,
                    'count': count,
                    'percentage': (count / len(recent_prompts)) * 100
                })

        return {
            'trends': sorted(trends, key=lambda x: x['count'], reverse=True),
            'most_common_category': most_common[0] if most_common[1] > 0 else None,
            'total_attacks': sum(category_counts.values()),
            'attack_rate': (sum(category_counts.values()) / len(recent_prompts)) * 100
        }
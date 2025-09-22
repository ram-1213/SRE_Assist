"""
Behavioral anomaly detection for user patterns - Working without sklearn
File: security/behavioral_analyzer.py
"""
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
import pickle
import os
import statistics
import logging

logger = logging.getLogger(__name__)


class SimpleBehavioralAnalyzer:
    """Simplified behavioral analyzer that works without sklearn"""

    def __init__(self):
        self.user_profiles = {}
        self.is_trained = False
        self.feature_names = [
            'avg_prompt_length', 'requests_per_hour', 'avg_time_between_requests',
            'risk_score_variance', 'code_request_ratio', 'hour_of_day',
            'session_duration', 'unique_topics_count'
        ]

        # Statistical thresholds for anomaly detection
        self.anomaly_thresholds = {
            'std_multiplier': 2.0,  # How many standard deviations = anomaly
            'min_samples': 10,      # Minimum samples needed for analysis
            'max_change_percent': 150  # Max percent change from baseline
        }

    def extract_behavioral_features(self, user_id: int, recent_activity: List[Dict]) -> List[float]:
        """Extract behavioral features from user activity"""
        if not recent_activity:
            return [0.0] * len(self.feature_names)

        try:
            # Calculate features
            prompt_lengths = [len(activity.get('content', '')) for activity in recent_activity]
            avg_prompt_length = statistics.mean(prompt_lengths) if prompt_lengths else 0

            # Time-based features
            timestamps = []
            for activity in recent_activity:
                if activity.get('timestamp'):
                    try:
                        ts = datetime.fromisoformat(activity['timestamp'])
                        timestamps.append(ts)
                    except:
                        continue

            if len(timestamps) > 1:
                time_diffs = [(timestamps[i] - timestamps[i - 1]).total_seconds()
                              for i in range(1, len(timestamps))]
                avg_time_between = statistics.mean(time_diffs) if time_diffs else 0
                session_duration = (timestamps[-1] - timestamps[0]).total_seconds() / 3600
                requests_per_hour = len(recent_activity) / max(session_duration, 0.1)
            else:
                avg_time_between = 0
                requests_per_hour = 1
                session_duration = 0

            # Risk score variance
            risk_scores = [activity.get('risk_score', 0) for activity in recent_activity
                          if activity.get('risk_score') is not None]
            risk_variance = statistics.variance(risk_scores) if len(risk_scores) > 1 else 0

            # Code request ratio
            code_indicators = ['```', 'def ', 'class ', 'import ', 'function', 'code']
            code_requests = sum(1 for activity in recent_activity
                               if any(indicator in activity.get('content', '').lower()
                                     for indicator in code_indicators))
            code_ratio = code_requests / len(recent_activity) if recent_activity else 0

            # Time of day (normalized)
            current_hour = datetime.now().hour / 24.0

            # Topic diversity (simple keyword-based)
            all_content = ' '.join([activity.get('content', '') for activity in recent_activity])
            topics = set()
            topic_keywords = ['security', 'code', 'data', 'web', 'api', 'database', 'ai', 'machine learning']
            for keyword in topic_keywords:
                if keyword in all_content.lower():
                    topics.add(keyword)
            unique_topics = len(topics)

            features = [
                avg_prompt_length,
                requests_per_hour,
                avg_time_between,
                risk_variance,
                code_ratio,
                current_hour,
                session_duration,
                unique_topics
            ]

            return features

        except Exception as e:
            logger.error(f"Error extracting behavioral features: {e}")
            return [0.0] * len(self.feature_names)

    def update_user_profile(self, user_id: int, recent_activity: List[Dict]):
        """Update user's behavioral profile"""
        features = self.extract_behavioral_features(user_id, recent_activity)

        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                'feature_history': [],
                'baseline_established': False,
                'last_update': datetime.now(),
                'baseline_stats': {}
            }

        profile = self.user_profiles[user_id]
        profile['feature_history'].append({
            'features': features,
            'timestamp': datetime.now().isoformat()
        })

        # Keep only last 100 entries
        if len(profile['feature_history']) > 100:
            profile['feature_history'] = profile['feature_history'][-100:]

        # Establish baseline after 10+ interactions
        if len(profile['feature_history']) >= self.anomaly_thresholds['min_samples']:
            profile['baseline_established'] = True
            self._calculate_baseline_stats(user_id)

        profile['last_update'] = datetime.now()

    def _calculate_baseline_stats(self, user_id: int):
        """Calculate baseline statistics for the user"""
        if user_id not in self.user_profiles:
            return

        profile = self.user_profiles[user_id]
        all_features = [entry['features'] for entry in profile['feature_history']]

        if len(all_features) < self.anomaly_thresholds['min_samples']:
            return

        # Calculate mean and standard deviation for each feature
        baseline_stats = {}
        for i, feature_name in enumerate(self.feature_names):
            feature_values = [features[i] for features in all_features if len(features) > i]
            if feature_values:
                baseline_stats[feature_name] = {
                    'mean': statistics.mean(feature_values),
                    'stdev': statistics.stdev(feature_values) if len(feature_values) > 1 else 0,
                    'median': statistics.median(feature_values),
                    'min': min(feature_values),
                    'max': max(feature_values)
                }

        profile['baseline_stats'] = baseline_stats
        self.is_trained = True

    def detect_anomaly(self, user_id: int, current_activity: List[Dict]) -> Dict:
        """Detect behavioral anomalies for a user using statistical methods"""
        if user_id not in self.user_profiles:
            return {
                'anomaly_detected': False,
                'anomaly_score': 0.0,
                'risk_level': 'unknown',
                'details': 'No user profile found'
            }

        profile = self.user_profiles[user_id]
        if not profile['baseline_established']:
            return {
                'anomaly_detected': False,
                'anomaly_score': 0.0,
                'risk_level': 'learning',
                'details': 'Still establishing baseline behavior'
            }

        try:
            current_features = self.extract_behavioral_features(user_id, current_activity)
            baseline_stats = profile['baseline_stats']

            anomalies = []
            anomaly_scores = []

            # Check each feature against baseline
            for i, feature_name in enumerate(self.feature_names):
                if i >= len(current_features):
                    continue

                current_value = current_features[i]
                if feature_name not in baseline_stats:
                    continue

                stats = baseline_stats[feature_name]
                mean = stats['mean']
                stdev = stats['stdev']

                if stdev > 0:
                    # Calculate z-score
                    z_score = abs((current_value - mean) / stdev)

                    # Check if it's an anomaly
                    if z_score > self.anomaly_thresholds['std_multiplier']:
                        severity = min(z_score / self.anomaly_thresholds['std_multiplier'], 3.0)
                        anomaly_score = min(severity * 33.33, 100)  # Scale to 0-100

                        direction = "higher" if current_value > mean else "lower"
                        anomalies.append({
                            'feature': feature_name,
                            'current': current_value,
                            'baseline_mean': mean,
                            'z_score': z_score,
                            'direction': direction,
                            'severity': severity
                        })
                        anomaly_scores.append(anomaly_score)

            # Calculate overall anomaly score
            if anomaly_scores:
                # Use the maximum anomaly score, but consider multiple anomalies
                max_score = max(anomaly_scores)
                multiple_anomalies_bonus = min(len(anomaly_scores) * 5, 20)
                overall_score = min(max_score + multiple_anomalies_bonus, 100)
            else:
                overall_score = 0

            # Determine risk level
            if overall_score > 70:
                risk_level = 'high'
            elif overall_score > 40:
                risk_level = 'medium'
            else:
                risk_level = 'low'

            # Generate details
            if anomalies:
                details = f"Detected {len(anomalies)} behavioral anomalies: "
                details += "; ".join([f"{a['feature']} is {a['direction']} than usual (z-score: {a['z_score']:.1f})"
                                    for a in anomalies[:3]])
            else:
                details = "Behavior is within normal parameters"

            return {
                'anomaly_detected': overall_score > 50,
                'anomaly_score': float(overall_score),
                'risk_level': risk_level,
                'details': details,
                'feature_analysis': {name: val for name, val in zip(self.feature_names, current_features)},
                'anomalies_found': anomalies
            }

        except Exception as e:
            logger.error(f"Error detecting anomaly: {e}")
            return {
                'anomaly_detected': False,
                'anomaly_score': 0.0,
                'risk_level': 'error',
                'details': f'Analysis error: {str(e)}'
            }

    def get_user_risk_profile(self, user_id: int) -> Dict:
        """Get comprehensive risk profile for a user"""
        if user_id not in self.user_profiles:
            return {'status': 'no_data'}

        profile = self.user_profiles[user_id]

        # Calculate recent risk scores
        recent_scores = []
        for entry in profile['feature_history'][-10:]:  # Last 10 interactions
            # Simple risk estimation based on feature values
            features = entry['features']
            if len(features) >= 4:  # Make sure we have enough features
                # Use risk variance and other indicators
                risk_estimate = min(features[3] * 10, 100)  # risk_score_variance
                recent_scores.append(risk_estimate)

        return {
            'status': 'baseline_established' if profile['baseline_established'] else 'learning',
            'total_interactions': len(profile['feature_history']),
            'avg_recent_risk': statistics.mean(recent_scores) if recent_scores else 0,
            'risk_trend': self._calculate_risk_trend(recent_scores),
            'last_update': profile['last_update'].isoformat(),
            'behavioral_summary': self._get_behavioral_summary(user_id)
        }

    def _calculate_risk_trend(self, recent_scores: List[float]) -> str:
        """Calculate if risk is increasing, decreasing, or stable"""
        if len(recent_scores) < 5:
            return 'insufficient_data'

        # Compare first half with second half
        mid = len(recent_scores) // 2
        first_half_avg = statistics.mean(recent_scores[:mid])
        second_half_avg = statistics.mean(recent_scores[mid:])

        if second_half_avg > first_half_avg * 1.2:
            return 'increasing'
        elif second_half_avg < first_half_avg * 0.8:
            return 'decreasing'
        else:
            return 'stable'

    def _get_behavioral_summary(self, user_id: int) -> Dict:
        """Get summary of user's behavioral patterns"""
        if user_id not in self.user_profiles:
            return {}

        profile = self.user_profiles[user_id]
        if not profile['feature_history']:
            return {}

        # Get all features
        all_features = [entry['features'] for entry in profile['feature_history']]
        if not all_features or len(all_features[0]) < len(self.feature_names):
            return {}

        # Calculate averages for each feature
        feature_averages = []
        for i in range(len(self.feature_names)):
            values = [features[i] for features in all_features if len(features) > i]
            if values:
                feature_averages.append(statistics.mean(values))
            else:
                feature_averages.append(0)

        return {
            'avg_prompt_length': feature_averages[0] if len(feature_averages) > 0 else 0,
            'typical_requests_per_hour': feature_averages[1] if len(feature_averages) > 1 else 0,
            'prefers_code_requests': (feature_averages[4] if len(feature_averages) > 4 else 0) > 0.3,
            'most_active_hour': int((feature_averages[5] if len(feature_averages) > 5 else 0) * 24),
            'session_consistency': 1 - min((feature_averages[6] if len(feature_averages) > 6 else 0) / 10, 1)
        }

    def save_profiles(self, filepath: str = "security/data/behavioral_profiles.pkl"):
        """Save user profiles to disk"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            # Convert datetime objects to strings for serialization
            serializable_profiles = {}
            for user_id, profile in self.user_profiles.items():
                serializable_profiles[user_id] = {
                    'feature_history': profile['feature_history'],
                    'baseline_established': profile['baseline_established'],
                    'last_update': profile['last_update'].isoformat(),
                    'baseline_stats': profile.get('baseline_stats', {})
                }

            data = {
                'user_profiles': serializable_profiles,
                'is_trained': self.is_trained,
                'thresholds': self.anomaly_thresholds
            }

            with open(filepath, 'wb') as f:
                pickle.dump(data, f)

            logger.info(f"Saved behavioral profiles for {len(self.user_profiles)} users")

        except Exception as e:
            logger.error(f"Error saving behavioral profiles: {e}")

    def load_profiles(self, filepath: str = "security/data/behavioral_profiles.pkl"):
        """Load user profiles from disk"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    data = pickle.load(f)

                # Restore datetime objects
                for user_id, profile in data['user_profiles'].items():
                    profile['last_update'] = datetime.fromisoformat(profile['last_update'])

                self.user_profiles = {int(k): v for k, v in data['user_profiles'].items()}
                self.is_trained = data.get('is_trained', False)
                if 'thresholds' in data:
                    self.anomaly_thresholds.update(data['thresholds'])

                logger.info(f"Loaded behavioral profiles for {len(self.user_profiles)} users")

        except Exception as e:
            logger.error(f"Error loading behavioral profiles: {e}")

    def record_feedback(self, was_threat: bool, detected_as_threat: bool):
        """Record human feedback for improving detection accuracy"""
        try:
            if not hasattr(self, 'feedback_history'):
                self.feedback_history = []

            feedback_entry = {
                'timestamp': datetime.now().isoformat(),
                'was_threat': was_threat,
                'detected_as_threat': detected_as_threat,
                'feedback_type': self._classify_feedback(was_threat, detected_as_threat)
            }

            self.feedback_history.append(feedback_entry)

            # Keep only last 100 feedback entries
            if len(self.feedback_history) > 100:
                self.feedback_history = self.feedback_history[-100:]

            logger.info(f"Recorded feedback: {feedback_entry['feedback_type']}")

        except Exception as e:
            logger.error(f"Error recording feedback: {e}")

    def _classify_feedback(self, was_threat: bool, detected_as_threat: bool) -> str:
        """Classify the type of feedback"""
        if was_threat and detected_as_threat:
            return "true_positive"
        elif not was_threat and not detected_as_threat:
            return "true_negative"
        elif not was_threat and detected_as_threat:
            return "false_positive"
        elif was_threat and not detected_as_threat:
            return "false_negative"
        else:
            return "unknown"

    def get_statistics(self) -> Dict:
        """Get analyzer statistics"""
        total_users = len(self.user_profiles)
        trained_users = sum(1 for p in self.user_profiles.values() if p['baseline_established'])

        return {
            'total_users': total_users,
            'users_with_baseline': trained_users,
            'is_trained': self.is_trained,
            'feature_count': len(self.feature_names),
            'anomaly_threshold': self.anomaly_thresholds['std_multiplier']
        }


# For backward compatibility
BehavioralAnalyzer = SimpleBehavioralAnalyzer
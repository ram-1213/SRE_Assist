"""
Real-time performance and security monitoring
File: security/performance_monitor.py
"""
import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
import logging
from collections import deque, defaultdict
import numpy as np

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        self.metrics_history = deque(maxlen=history_size)
        self.security_events = deque(maxlen=history_size)
        self.response_times = deque(maxlen=history_size)
        self.detection_accuracy = deque(maxlen=history_size)
        self.threat_counts = defaultdict(int)
        self.start_time = datetime.now()
        self.total_requests = 0
        self.blocked_requests = 0
        self.false_positives = 0
        self.false_negatives = 0

        # Performance thresholds
        self.thresholds = {
            'max_response_time': 5.0,  # seconds
            'max_cpu_usage': 80.0,  # percentage
            'max_memory_usage': 80.0,  # percentage
            'min_accuracy': 90.0  # percentage
        }

        # Start monitoring thread
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()

    def record_request(self, request_type: str, response_time: float, security_result: Dict):
        """Record a security analysis request with safe handling"""
        if security_result is None:
            security_result = {}

        self.total_requests += 1
        self.response_times.append(response_time)

        # Safe threat detection checks
        threat_detected = (
                security_result.get('injection_detected', False) or
                (security_result.get('sql_injection') and security_result['sql_injection'].get('detected', False)) or
                (security_result.get('data_poisoning') and security_result['data_poisoning'].get('detected', False))
        )

        if threat_detected:
            self.blocked_requests += 1
            threat_type = self._classify_threat_type(security_result)
            self.threat_counts[threat_type] += 1

        # Record metrics safely
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'request_type': request_type,
            'response_time': response_time,
            'threat_detected': threat_detected,
            'risk_score': security_result.get('risk_score', 0),
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent
        }

        self.metrics_history.append(metrics)

        # Record security event if threat detected
        if threat_detected:
            event = {
                'timestamp': datetime.now().isoformat(),
                'threat_type': threat_type,
                'risk_score': security_result.get('risk_score', 0),
                'details': security_result
            }
            self.security_events.append(event)

    def record_feedback(self, was_threat: bool, detected_as_threat: bool):
        """Record human feedback for accuracy calculation"""
        if was_threat and detected_as_threat:
            # True positive
            pass
        elif not was_threat and not detected_as_threat:
            # True negative
            pass
        elif not was_threat and detected_as_threat:
            # False positive
            self.false_positives += 1
        elif was_threat and not detected_as_threat:
            # False negative
            self.false_negatives += 1

        # Calculate accuracy
        total_feedback = self.false_positives + self.false_negatives + max(1,
                                                                           self.total_requests - self.false_positives - self.false_negatives)
        accuracy = (total_feedback - self.false_positives - self.false_negatives) / total_feedback * 100
        self.detection_accuracy.append(accuracy)

    def _classify_threat_type(self, security_result: Dict) -> str:
        """Classify the type of threat detected"""
        if security_result.get('injection_detected'):
            return 'prompt_injection'
        elif security_result.get('sql_injection', {}).get('detected'):
            return 'sql_injection'
        elif security_result.get('data_poisoning', {}).get('detected'):
            return 'data_poisoning'
        elif security_result.get('code_vulnerabilities'):
            return 'code_vulnerability'
        else:
            return 'unknown_threat'

    def _monitor_system(self):
        """Background system monitoring"""
        while self.monitoring:
            try:
                time.sleep(10)  # Monitor every 10 seconds

                # Check system health
                cpu_usage = psutil.cpu_percent()
                memory_usage = psutil.virtual_memory().percent

                # Log alerts if thresholds exceeded
                if cpu_usage > self.thresholds['max_cpu_usage']:
                    logger.warning(f"High CPU usage: {cpu_usage:.1f}%")

                if memory_usage > self.thresholds['max_memory_usage']:
                    logger.warning(f"High memory usage: {memory_usage:.1f}%")

                # Check response time trends
                if len(self.response_times) > 10:
                    avg_response_time = np.mean(list(self.response_times)[-10:])
                    if avg_response_time > self.thresholds['max_response_time']:
                        logger.warning(f"Slow response times: {avg_response_time:.2f}s")

            except Exception as e:
                logger.error(f"System monitoring error: {e}")

    def get_performance_stats(self) -> Dict:
        """Get current performance statistics"""
        if not self.metrics_history:
            return {'status': 'no_data'}

        recent_metrics = list(self.metrics_history)[-100:]  # Last 100 requests

        # Calculate averages
        avg_response_time = np.mean([m['response_time'] for m in recent_metrics])
        avg_cpu = np.mean([m['cpu_usage'] for m in recent_metrics])
        avg_memory = np.mean([m['memory_usage'] for m in recent_metrics])
        avg_risk_score = np.mean([m['risk_score'] for m in recent_metrics])

        # Calculate threat detection rate
        threats_detected = sum(1 for m in recent_metrics if m['threat_detected'])
        detection_rate = (threats_detected / len(recent_metrics)) * 100 if recent_metrics else 0

        # Calculate uptime
        uptime = datetime.now() - self.start_time

        return {
            'uptime_hours': uptime.total_seconds() / 3600,
            'total_requests': self.total_requests,
            'blocked_requests': self.blocked_requests,
            'block_rate_percent': (self.blocked_requests / max(1, self.total_requests)) * 100,
            'avg_response_time': avg_response_time,
            'avg_cpu_usage': avg_cpu,
            'avg_memory_usage': avg_memory,
            'avg_risk_score': avg_risk_score,
            'detection_rate': detection_rate,
            'current_accuracy': list(self.detection_accuracy)[-1] if self.detection_accuracy else 0,
            'false_positive_rate': (self.false_positives / max(1, self.total_requests)) * 100,
            'false_negative_rate': (self.false_negatives / max(1, self.total_requests)) * 100
        }

    def get_security_dashboard_data(self) -> Dict:
        """Get data for security dashboard visualization"""
        # Time series data for charts
        timestamps = []
        response_times = []
        risk_scores = []
        cpu_usage = []
        memory_usage = []

        for metric in list(self.metrics_history)[-50:]:  # Last 50 data points
            timestamps.append(metric['timestamp'])
            response_times.append(metric['response_time'])
            risk_scores.append(metric['risk_score'])
            cpu_usage.append(metric['cpu_usage'])
            memory_usage.append(metric['memory_usage'])

        # Threat distribution
        threat_distribution = dict(self.threat_counts)

        # Recent security events
        recent_events = list(self.security_events)[-10:]

        # Performance alerts
        alerts = []
        if len(self.response_times) > 0:
            avg_response = np.mean(list(self.response_times)[-10:])
            if avg_response > self.thresholds['max_response_time']:
                alerts.append(f"Slow response times: {avg_response:.2f}s")

        current_accuracy = list(self.detection_accuracy)[-1] if self.detection_accuracy else 100
        if current_accuracy < self.thresholds['min_accuracy']:
            alerts.append(f"Low detection accuracy: {current_accuracy:.1f}%")

        return {
            'time_series': {
                'timestamps': timestamps,
                'response_times': response_times,
                'risk_scores': risk_scores,
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage
            },
            'threat_distribution': threat_distribution,
            'recent_events': recent_events,
            'alerts': alerts,
            'system_health': {
                'status': 'healthy' if len(alerts) == 0 else 'warning',
                'cpu_ok': psutil.cpu_percent() < self.thresholds['max_cpu_usage'],
                'memory_ok': psutil.virtual_memory().percent < self.thresholds['max_memory_usage'],
                'response_time_ok': np.mean(list(self.response_times)[-10:]) < self.thresholds[
                    'max_response_time'] if self.response_times else True
            }
        }

    def get_benchmark_comparison(self) -> Dict:
        """Compare against industry benchmarks"""
        stats = self.get_performance_stats()

        # Industry benchmark estimates
        benchmarks = {
            'response_time': 2.0,  # seconds
            'accuracy': 95.0,  # percentage
            'false_positive_rate': 5.0,  # percentage
            'detection_rate': 85.0  # percentage
        }

        comparison = {}
        for metric, benchmark in benchmarks.items():
            if metric == 'response_time':
                current = stats.get('avg_response_time', 0)
                comparison[metric] = {
                    'current': current,
                    'benchmark': benchmark,
                    'better': current < benchmark,
                    'difference': ((current - benchmark) / benchmark) * 100
                }
            elif metric == 'accuracy':
                current = stats.get('current_accuracy', 0)
                comparison[metric] = {
                    'current': current,
                    'benchmark': benchmark,
                    'better': current > benchmark,
                    'difference': current - benchmark
                }
            elif metric == 'false_positive_rate':
                current = stats.get('false_positive_rate', 0)
                comparison[metric] = {
                    'current': current,
                    'benchmark': benchmark,
                    'better': current < benchmark,
                    'difference': current - benchmark
                }
            elif metric == 'detection_rate':
                current = stats.get('detection_rate', 0)
                comparison[metric] = {
                    'current': current,
                    'benchmark': benchmark,
                    'better': current > benchmark,
                    'difference': current - benchmark
                }

        return comparison

    def export_metrics(self, filepath: str):
        """Export metrics to JSON file"""
        try:
            export_data = {
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'total_requests': self.total_requests,
                    'uptime_hours': (datetime.now() - self.start_time).total_seconds() / 3600
                },
                'performance_stats': self.get_performance_stats(),
                'metrics_history': list(self.metrics_history),
                'security_events': list(self.security_events),
                'threat_counts': dict(self.threat_counts)
            }

            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)

            logger.info(f"Exported metrics to {filepath}")

        except Exception as e:
            logger.error(f"Error exporting metrics: {e}")

    def stop_monitoring(self):
        """Stop the background monitoring"""
        self.monitoring = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=1)

    def get_real_time_metrics(self) -> Dict:
        """Get real-time system metrics"""
        return {
            'timestamp': datetime.now().isoformat(),
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {},
            'active_connections': len(psutil.net_connections()),
            'process_count': len(psutil.pids()),
            'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
        }
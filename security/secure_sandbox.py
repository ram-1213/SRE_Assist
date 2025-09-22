"""
Windows-compatible secure sandboxed code execution
File: security/secure_sandbox.py
"""
import subprocess
import tempfile
import os
import time
import signal
import threading
from typing import Dict, Optional, Tuple
import json
import logging
import sys
import platform

logger = logging.getLogger(__name__)

class CodeSandbox:
    def __init__(self):
        self.timeout_seconds = 30
        self.max_memory_mb = 128
        self.max_output_size = 10000
        self.is_windows = platform.system() == "Windows"
        self.allowed_imports = {
            'math', 'random', 'datetime', 'json', 'base64', 'hashlib',
            'collections', 'itertools', 'functools', 're', 'string',
            'urllib.parse', 'uuid', 'time'
        }
        self.blocked_functions = {
            'eval', 'exec', 'compile', '__import__', 'open', 'input',
            'raw_input', 'file', 'reload', 'vars', 'dir', 'globals',
            'locals', 'delattr', 'setattr', 'getattr', 'hasattr'
        }

    def execute_python_safely(self, code: str) -> Dict:
        """Execute Python code in a restricted environment"""
        try:
            # Pre-execution security checks
            security_check = self._pre_execution_security_check(code)
            if not security_check['safe']:
                return {
                    'success': False,
                    'output': '',
                    'error': f"Security violation: {security_check['reason']}",
                    'execution_time': 0,
                    'memory_used': 0,
                    'security_violations': security_check['violations']
                }

            # Create temporary file for code execution
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                # Wrap code with security restrictions
                wrapped_code = self._wrap_code_with_restrictions(code)
                f.write(wrapped_code)
                temp_file = f.name

            try:
                # Execute in subprocess with restrictions
                result = self._execute_in_subprocess(temp_file)
                return result

            finally:
                # Clean up temp file
                try:
                    os.unlink(temp_file)
                except:
                    pass

        except Exception as e:
            logger.error(f"Sandbox execution error: {e}")
            return {
                'success': False,
                'output': '',
                'error': f"Sandbox error: {str(e)}",
                'execution_time': 0,
                'memory_used': 0,
                'security_violations': []
            }

    def _pre_execution_security_check(self, code: str) -> Dict:
        """Perform security checks before execution"""
        violations = []

        # Check for blocked functions
        code_lower = code.lower()
        for blocked_func in self.blocked_functions:
            if blocked_func in code_lower:
                violations.append(f"Blocked function: {blocked_func}")

        # Check for dangerous imports
        import_lines = [line.strip() for line in code.split('\n') if line.strip().startswith('import') or 'import' in line]
        for line in import_lines:
            if 'os' in line or 'sys' in line or 'subprocess' in line:
                violations.append(f"Dangerous import: {line}")

        # Check for file operations
        file_operations = ['open(', 'file(', 'FileIO', 'with open']
        for op in file_operations:
            if op in code:
                violations.append(f"File operation detected: {op}")

        # Check for network operations
        network_keywords = ['urllib', 'requests', 'socket', 'http', 'ftp']
        for keyword in network_keywords:
            if keyword in code_lower:
                violations.append(f"Network operation: {keyword}")

        # Check for system calls
        system_calls = ['os.system', 'subprocess', 'popen', 'call']
        for call in system_calls:
            if call in code_lower:
                violations.append(f"System call: {call}")

        return {
            'safe': len(violations) == 0,
            'violations': violations,
            'reason': violations[0] if violations else None
        }

    def _wrap_code_with_restrictions(self, code: str) -> str:
        """Wrap user code with security restrictions - Windows compatible"""

        if self.is_windows:
            # Windows-compatible wrapper (no resource module)
            wrapper = f'''
import sys
import time

# Set timeout using threading for Windows
import threading
import signal

# Restricted builtins
restricted_builtins = {{
    'print': print,
    'len': len,
    'str': str,
    'int': int,
    'float': float,
    'bool': bool,
    'list': list,
    'dict': dict,
    'tuple': tuple,
    'set': set,
    'range': range,
    'enumerate': enumerate,
    'zip': zip,
    'map': map,
    'filter': filter,
    'sorted': sorted,
    'sum': sum,
    'min': min,
    'max': max,
    'abs': abs,
    'round': round,
    'type': type,
    'isinstance': isinstance
}}

# Block dangerous functions
def blocked_function(*args, **kwargs):
    raise PermissionError("Function blocked for security")

blocked_functions = [{', '.join([f'"{func}"' for func in self.blocked_functions])}]
for func_name in blocked_functions:
    restricted_builtins[func_name] = blocked_function

# Override builtins
import builtins
original_builtins = dict(builtins.__dict__)
builtins.__dict__.clear()
builtins.__dict__.update(restricted_builtins)

start_time = time.time()
output_buffer = []

# Capture stdout
class OutputCapture:
    def __init__(self, max_size):
        self.max_size = max_size
        self.size = 0
        
    def write(self, text):
        global output_buffer
        if self.size + len(text) > self.max_size:
            raise MemoryError("Output size limit exceeded")
        output_buffer.append(text)
        self.size += len(text)
        
    def flush(self):
        pass

sys.stdout = OutputCapture({self.max_output_size})

try:
    # User code starts here
{code}
    
    # User code ends here
    execution_time = time.time() - start_time
    print(f"\\n__EXECUTION_STATS__{{execution_time:{execution_time:.3f}}}")
    
except Exception as e:
    print(f"\\n__ERROR__{{type:{type(e).__name__}, message:{str(e)}}}")
    
finally:
    # Restore builtins
    builtins.__dict__.clear()
    builtins.__dict__.update(original_builtins)
'''
        else:
            # Unix/Linux wrapper with resource limits
            wrapper = f'''
import sys
import signal
import time

# Try to import resource for Unix systems
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, ({self.timeout_seconds}, {self.timeout_seconds}))
    resource.setrlimit(resource.RLIMIT_AS, ({self.max_memory_mb * 1024 * 1024}, {self.max_memory_mb * 1024 * 1024}))
except:
    pass

# Restricted builtins
restricted_builtins = {{
    'print': print,
    'len': len,
    'str': str,
    'int': int,
    'float': float,
    'bool': bool,
    'list': list,
    'dict': dict,
    'tuple': tuple,
    'set': set,
    'range': range,
    'enumerate': enumerate,
    'zip': zip,
    'map': map,
    'filter': filter,
    'sorted': sorted,
    'sum': sum,
    'min': min,
    'max': max,
    'abs': abs,
    'round': round,
    'type': type,
    'isinstance': isinstance
}}

# Block dangerous functions
def blocked_function(*args, **kwargs):
    raise PermissionError("Function blocked for security")

blocked_functions = [{', '.join([f'"{func}"' for func in self.blocked_functions])}]
for func_name in blocked_functions:
    restricted_builtins[func_name] = blocked_function

# Override builtins
import builtins
original_builtins = dict(builtins.__dict__)
builtins.__dict__.clear()
builtins.__dict__.update(restricted_builtins)

# Timeout handler
def timeout_handler(signum, frame):
    raise TimeoutError("Code execution timed out")

try:
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm({self.timeout_seconds})
except:
    pass  # Windows doesn't support SIGALRM

start_time = time.time()
output_buffer = []

# Capture stdout
class OutputCapture:
    def __init__(self, max_size):
        self.max_size = max_size
        self.size = 0
        
    def write(self, text):
        global output_buffer
        if self.size + len(text) > self.max_size:
            raise MemoryError("Output size limit exceeded")
        output_buffer.append(text)
        self.size += len(text)
        
    def flush(self):
        pass

sys.stdout = OutputCapture({self.max_output_size})

try:
    # User code starts here
{code}
    
    # User code ends here
    execution_time = time.time() - start_time
    print(f"\\n__EXECUTION_STATS__{{execution_time:{execution_time:.3f}}}")
    
except Exception as e:
    print(f"\\n__ERROR__{{type:{type(e).__name__}, message:{str(e)}}}")
    
finally:
    try:
        signal.alarm(0)  # Cancel timeout
    except:
        pass
    # Restore builtins
    builtins.__dict__.clear()
    builtins.__dict__.update(original_builtins)
'''

        return wrapper

    def _execute_in_subprocess(self, temp_file: str) -> Dict:
        """Execute code in subprocess with monitoring"""
        start_time = time.time()

        try:
            # Create subprocess arguments
            if self.is_windows:
                # Windows subprocess
                process = subprocess.Popen(
                    [sys.executable, temp_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if hasattr(subprocess, 'CREATE_NEW_PROCESS_GROUP') else 0
                )
            else:
                # Unix subprocess with resource limits
                process = subprocess.Popen(
                    [sys.executable, temp_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    preexec_fn=self._set_process_limits
                )

            # Wait for completion with timeout
            try:
                stdout, stderr = process.communicate(timeout=self.timeout_seconds)
                execution_time = time.time() - start_time

                # Parse output for stats and errors
                result = self._parse_execution_output(stdout, stderr, execution_time)
                result['success'] = process.returncode == 0

                return result

            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return {
                    'success': False,
                    'output': '',
                    'error': 'Code execution timed out',
                    'execution_time': self.timeout_seconds,
                    'memory_used': 0,
                    'security_violations': ['Timeout exceeded']
                }

        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': f'Execution error: {str(e)}',
                'execution_time': time.time() - start_time,
                'memory_used': 0,
                'security_violations': []
            }

    def _set_process_limits(self):
        """Set resource limits for the subprocess (Unix only)"""
        if not self.is_windows:
            try:
                import resource
                # Set CPU time limit
                resource.setrlimit(resource.RLIMIT_CPU, (self.timeout_seconds, self.timeout_seconds))
                # Set memory limit
                resource.setrlimit(resource.RLIMIT_AS, (self.max_memory_mb * 1024 * 1024, self.max_memory_mb * 1024 * 1024))
            except:
                pass

    def _parse_execution_output(self, stdout: str, stderr: str, execution_time: float) -> Dict:
        """Parse execution output for stats and security violations"""
        output_lines = stdout.split('\n')
        clean_output = []
        parsed_stats = {'execution_time': execution_time, 'memory_used': 0}
        security_violations = []

        for line in output_lines:
            if line.startswith('__EXECUTION_STATS__'):
                try:
                    stats_str = line.replace('__EXECUTION_STATS__', '')
                    # Parse basic stats
                    if 'execution_time:' in stats_str:
                        parsed_stats['execution_time'] = float(stats_str.split('execution_time:')[1].split('}')[0])
                except:
                    pass
            elif line.startswith('__ERROR__'):
                try:
                    error_str = line.replace('__ERROR__', '')
                    if 'PermissionError' in error_str:
                        security_violations.append('Attempted to access blocked function')
                except:
                    pass
            else:
                clean_output.append(line)

        return {
            'output': '\n'.join(clean_output).strip(),
            'error': stderr.strip() if stderr else '',
            'execution_time': parsed_stats['execution_time'],
            'memory_used': parsed_stats['memory_used'],
            'security_violations': security_violations
        }

    def analyze_code_runtime_behavior(self, code: str) -> Dict:
        """Analyze code for runtime security behavior"""
        # Add monitoring code to detect suspicious runtime behavior
        monitoring_code = f'''
import sys
import time

# Runtime behavior monitoring
runtime_violations = []
function_calls = []

# Monitor function calls
original_setattr = setattr
def monitored_setattr(obj, name, value):
    function_calls.append(f"setattr: {{obj}}.{{name}}")
    if name.startswith('_'):
        runtime_violations.append(f"Attempted to modify private attribute: {{name}}")
    return original_setattr(obj, name, value)

setattr = monitored_setattr

# User code
try:
{code}
except Exception as e:
    print(f"Runtime error: {{e}}")

# Report violations
if runtime_violations:
    print("\\n__RUNTIME_VIOLATIONS__" + str(runtime_violations))
if function_calls:
    print("\\n__FUNCTION_CALLS__" + str(function_calls[:10]))  # Limit output
'''

        result = self.execute_python_safely(monitoring_code)

        # Parse runtime violations
        runtime_violations = []
        if '__RUNTIME_VIOLATIONS__' in result['output']:
            try:
                violations_str = result['output'].split('__RUNTIME_VIOLATIONS__')[1].split('\n')[0]
                runtime_violations = eval(violations_str)
            except:
                pass

        return {
            'execution_result': result,
            'runtime_violations': runtime_violations,
            'suspicious_behavior': len(runtime_violations) > 0,
            'risk_score': min(len(runtime_violations) * 25, 100)
        }

    def get_sandbox_stats(self) -> Dict:
        """Get sandbox usage statistics"""
        return {
            'platform': platform.system(),
            'timeout_seconds': self.timeout_seconds,
            'max_memory_mb': self.max_memory_mb,
            'max_output_size': self.max_output_size,
            'blocked_functions_count': len(self.blocked_functions),
            'allowed_imports_count': len(self.allowed_imports),
            'windows_compatible': self.is_windows
        }
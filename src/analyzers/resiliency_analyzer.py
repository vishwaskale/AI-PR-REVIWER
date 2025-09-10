"""Resiliency patterns analyzer for microservices."""

import re
from typing import List, Dict, Any, Optional
from .base_analyzer import BaseAnalyzer, AnalysisResult, Issue, Severity, Category


class ResiliencyAnalyzer(BaseAnalyzer):
    """Analyzer for resiliency patterns in microservices."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.patterns = config.get('patterns', [])
        self.resiliency_patterns = self._load_resiliency_patterns()
    
    def can_analyze(self, filename: str) -> bool:
        """Check if this analyzer can analyze resiliency patterns."""
        # Focus on code files that might contain resiliency patterns
        code_extensions = ['.java', '.py', '.js', '.ts', '.go', '.cs', '.scala']
        config_extensions = ['.yml', '.yaml', '.json', '.properties']
        
        return (any(filename.endswith(ext) for ext in code_extensions + config_extensions) or
                'docker' in filename.lower() or
                'k8s' in filename.lower() or
                'kubernetes' in filename.lower())
    
    def analyze_file(self, filename: str, content: str, diff: Optional[str] = None) -> AnalysisResult:
        """Analyze a file for resiliency patterns."""
        issues = []
        
        try:
            lines = content.split('\n')
            
            # Run different resiliency pattern checks
            if 'circuit_breaker' in self.patterns:
                issues.extend(self._analyze_circuit_breaker(filename, content, lines, diff))
            
            if 'retry_with_backoff' in self.patterns:
                issues.extend(self._analyze_retry_patterns(filename, content, lines, diff))
            
            if 'bulkhead' in self.patterns:
                issues.extend(self._analyze_bulkhead_patterns(filename, content, lines, diff))
            
            if 'timeout' in self.patterns:
                issues.extend(self._analyze_timeout_patterns(filename, content, lines, diff))
            
            if 'rate_limiting' in self.patterns:
                issues.extend(self._analyze_rate_limiting(filename, content, lines, diff))
            
            if 'graceful_degradation' in self.patterns:
                issues.extend(self._analyze_graceful_degradation(filename, content, lines, diff))
            
            if 'health_checks' in self.patterns:
                issues.extend(self._analyze_health_checks(filename, content, lines, diff))
            
            if 'chaos_engineering' in self.patterns:
                issues.extend(self._analyze_chaos_engineering(filename, content, lines, diff))
            
            # Calculate confidence score
            confidence = self._calculate_confidence(filename, content, issues)
            
            # Generate metrics
            metrics = self._generate_metrics(filename, content, issues)
            
        except Exception as e:
            issues.append(Issue(
                filename=filename,
                line_number=1,
                column=None,
                severity=Severity.MINOR,
                category=Category.RELIABILITY,
                title="Resiliency Analysis Error",
                description=f"Error analyzing resiliency patterns: {str(e)}",
                recommendation="Review file structure and resiliency implementations",
                confidence=0.5,
                rule_id="RESILIENCY_ANALYSIS_ERROR"
            ))
            confidence = 0.5
            metrics = {}
        
        summary = self._generate_summary(issues)
        
        return AnalysisResult(
            issues=issues,
            confidence_score=confidence,
            summary=summary,
            metrics=metrics
        )
    
    def _analyze_circuit_breaker(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze circuit breaker pattern implementation."""
        issues = []
        
        # Check for HTTP clients without circuit breaker
        has_http_client = bool(re.search(r'RestTemplate|WebClient|HttpClient|@FeignClient', content))
        has_circuit_breaker = bool(re.search(r'CircuitBreaker|@HystrixCommand|@CircuitBreaker|Resilience4j', content))
        
        if has_http_client and not has_circuit_breaker:
            issues.append(Issue(
                filename=filename,
                line_number=1,
                column=None,
                severity=Severity.MAJOR,
                category=Category.RELIABILITY,
                title="Missing Circuit Breaker",
                description="HTTP client without circuit breaker protection",
                recommendation="Implement circuit breaker pattern (Hystrix, Resilience4j) to prevent cascading failures",
                confidence=0.8,
                rule_id="MISSING_CIRCUIT_BREAKER"
            ))
        
        # Check for proper circuit breaker configuration
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            if re.search(r'@HystrixCommand|@CircuitBreaker', line):
                # Check if fallback is defined
                if 'fallback' not in line.lower() and 'fallbackMethod' not in content:
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.MINOR,
                        category=Category.RELIABILITY,
                        title="Circuit Breaker Without Fallback",
                        description="Circuit breaker without fallback method",
                        recommendation="Define fallback methods for graceful degradation when circuit is open",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.7,
                        rule_id="CB_NO_FALLBACK"
                    ))
        
        return issues
    
    def _analyze_retry_patterns(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze retry pattern implementation."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Check for retry without backoff
            if re.search(r'@Retryable|retry\(', line, re.IGNORECASE):
                if 'backoff' not in line.lower() and 'delay' not in line.lower():
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.MINOR,
                        category=Category.RELIABILITY,
                        title="Retry Without Backoff",
                        description="Retry mechanism without exponential backoff",
                        recommendation="Implement exponential backoff to avoid overwhelming failing services",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.8,
                        rule_id="RETRY_NO_BACKOFF"
                    ))
            
            # Check for infinite retry
            if re.search(r'while.*true.*retry|for.*retry', line, re.IGNORECASE):
                issues.append(Issue(
                    filename=filename,
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.RELIABILITY,
                    title="Potential Infinite Retry",
                    description="Retry logic that might run indefinitely",
                    recommendation="Set maximum retry attempts and implement circuit breaker",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.7,
                    rule_id="INFINITE_RETRY"
                ))
        
        return issues
    
    def _analyze_bulkhead_patterns(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze bulkhead pattern implementation."""
        issues = []
        
        # Check for thread pool isolation
        has_async_calls = bool(re.search(r'@Async|CompletableFuture|ExecutorService', content))
        has_thread_pool_config = bool(re.search(r'ThreadPoolExecutor|@EnableAsync.*executor', content))
        
        if has_async_calls and not has_thread_pool_config:
            issues.append(Issue(
                filename=filename,
                line_number=1,
                column=None,
                severity=Severity.MINOR,
                category=Category.PERFORMANCE,
                title="Missing Thread Pool Configuration",
                description="Async operations without dedicated thread pool configuration",
                recommendation="Configure separate thread pools for different types of operations (bulkhead pattern)",
                confidence=0.6,
                rule_id="MISSING_THREAD_POOL"
            ))
        
        # Check for resource isolation
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            if re.search(r'@HystrixCommand', line):
                if 'threadPoolKey' not in line:
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.SUGGESTION,
                        category=Category.PERFORMANCE,
                        title="Missing Thread Pool Isolation",
                        description="Hystrix command without thread pool isolation",
                        recommendation="Use threadPoolKey to isolate different operations",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.6,
                        rule_id="MISSING_THREAD_ISOLATION"
                    ))
        
        return issues
    
    def _analyze_timeout_patterns(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze timeout pattern implementation."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Check for HTTP clients without timeout
            if re.search(r'RestTemplate|WebClient|HttpClient', line):
                if 'timeout' not in content.lower() and 'connectTimeout' not in content.lower():
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.MAJOR,
                        category=Category.RELIABILITY,
                        title="Missing Timeout Configuration",
                        description="HTTP client without timeout configuration",
                        recommendation="Configure connection and read timeouts to prevent hanging requests",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.8,
                        rule_id="MISSING_TIMEOUT"
                    ))
            
            # Check for database operations without timeout
            if re.search(r'@Query|@Transactional', line):
                if 'timeout' not in line.lower():
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.MINOR,
                        category=Category.PERFORMANCE,
                        title="Database Operation Without Timeout",
                        description="Database operation without timeout configuration",
                        recommendation="Set appropriate timeouts for database operations",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.6,
                        rule_id="DB_NO_TIMEOUT"
                    ))
        
        return issues
    
    def _analyze_rate_limiting(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze rate limiting implementation."""
        issues = []
        
        # Check for public APIs without rate limiting
        has_public_endpoints = bool(re.search(r'@RequestMapping|@GetMapping|@PostMapping', content))
        has_rate_limiting = bool(re.search(r'@RateLimiter|RateLimiting|Bucket4j|Guava.*RateLimiter', content))
        
        if has_public_endpoints and not has_rate_limiting:
            issues.append(Issue(
                filename=filename,
                line_number=1,
                column=None,
                severity=Severity.MINOR,
                category=Category.SECURITY,
                title="Missing Rate Limiting",
                description="Public API endpoints without rate limiting",
                recommendation="Implement rate limiting to protect against abuse and ensure fair usage",
                confidence=0.6,
                rule_id="MISSING_RATE_LIMITING"
            ))
        
        return issues
    
    def _analyze_graceful_degradation(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze graceful degradation patterns."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Check for fallback mechanisms
            if re.search(r'catch.*Exception', line):
                # Look for graceful degradation in exception handling
                next_lines = lines[i:i+5] if i < len(lines) - 5 else lines[i:]
                has_fallback = any(re.search(r'fallback|default|alternative', next_line, re.IGNORECASE) 
                                 for next_line in next_lines)
                
                if not has_fallback:
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.SUGGESTION,
                        category=Category.RELIABILITY,
                        title="Missing Graceful Degradation",
                        description="Exception handling without graceful degradation",
                        recommendation="Provide fallback behavior or default responses when operations fail",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.5,
                        rule_id="MISSING_GRACEFUL_DEGRADATION"
                    ))
        
        return issues
    
    def _analyze_health_checks(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze health check implementation."""
        issues = []
        
        # Check for missing health checks in services
        is_service = bool(re.search(r'@Service|@RestController|@Component', content))
        has_health_check = bool(re.search(r'/health|/actuator|HealthIndicator|@Health', content))
        
        if is_service and not has_health_check:
            issues.append(Issue(
                filename=filename,
                line_number=1,
                column=None,
                severity=Severity.MINOR,
                category=Category.RELIABILITY,
                title="Missing Health Check",
                description="Service component without health check endpoint",
                recommendation="Implement health check endpoints for monitoring and load balancer integration",
                confidence=0.7,
                rule_id="MISSING_HEALTH_CHECK"
            ))
        
        # Check for comprehensive health checks
        if has_health_check:
            has_dependency_check = bool(re.search(r'database|redis|kafka|elasticsearch', content, re.IGNORECASE))
            if has_dependency_check and 'HealthIndicator' not in content:
                issues.append(Issue(
                    filename=filename,
                    line_number=1,
                    column=None,
                    severity=Severity.SUGGESTION,
                    category=Category.RELIABILITY,
                    title="Incomplete Health Check",
                    description="Health check doesn't verify external dependencies",
                    recommendation="Include dependency health checks (database, message queues, etc.)",
                    confidence=0.6,
                    rule_id="INCOMPLETE_HEALTH_CHECK"
                ))
        
        return issues
    
    def _analyze_chaos_engineering(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze chaos engineering readiness."""
        issues = []
        
        # Check for chaos engineering annotations or configurations
        has_chaos_annotations = bool(re.search(r'@ChaosMonkey|@AssaultException|ChaosEngineering', content))
        
        # This is more of a suggestion for services that should be chaos-ready
        is_critical_service = bool(re.search(r'payment|order|user|auth|billing', filename, re.IGNORECASE))
        
        if is_critical_service and not has_chaos_annotations:
            issues.append(Issue(
                filename=filename,
                line_number=1,
                column=None,
                severity=Severity.SUGGESTION,
                category=Category.RELIABILITY,
                title="Chaos Engineering Readiness",
                description="Critical service without chaos engineering preparation",
                recommendation="Consider adding chaos engineering tools (Chaos Monkey) to test resilience",
                confidence=0.4,
                rule_id="CHAOS_ENGINEERING_SUGGESTION"
            ))
        
        return issues
    
    def _calculate_confidence(self, filename: str, content: str, issues: List[Issue]) -> float:
        """Calculate confidence score for resiliency analysis."""
        base_confidence = 0.6
        
        # Higher confidence for files with resiliency patterns
        resiliency_keywords = ['circuit', 'retry', 'timeout', 'fallback', 'resilience', 'hystrix']
        if any(keyword in content.lower() for keyword in resiliency_keywords):
            base_confidence += 0.2
        
        # Higher confidence for service files
        if any(pattern in filename.lower() for pattern in ['service', 'client', 'controller']):
            base_confidence += 0.1
        
        # Lower confidence for config files
        if filename.endswith(('.yml', '.yaml', '.json', '.properties')):
            base_confidence -= 0.1
        
        return min(1.0, max(0.1, base_confidence))
    
    def _generate_metrics(self, filename: str, content: str, issues: List[Issue]) -> Dict[str, Any]:
        """Generate resiliency-specific metrics."""
        metrics = {
            'total_lines': len(content.split('\n')),
            'issues_found': len(issues),
            'reliability_issues': len([i for i in issues if i.category == Category.RELIABILITY]),
            'performance_issues': len([i for i in issues if i.category == Category.PERFORMANCE]),
            'security_issues': len([i for i in issues if i.category == Category.SECURITY])
        }
        
        # Count resiliency patterns
        metrics.update({
            'circuit_breakers': len(re.findall(r'CircuitBreaker|@HystrixCommand|@CircuitBreaker', content)),
            'retry_mechanisms': len(re.findall(r'@Retryable|retry\(', content, re.IGNORECASE)),
            'timeout_configs': len(re.findall(r'timeout|connectTimeout|readTimeout', content, re.IGNORECASE)),
            'fallback_methods': len(re.findall(r'fallback|fallbackMethod', content, re.IGNORECASE)),
            'health_checks': len(re.findall(r'/health|/actuator|HealthIndicator', content)),
            'async_operations': len(re.findall(r'@Async|CompletableFuture|ExecutorService', content))
        })
        
        return metrics
    
    def _load_resiliency_patterns(self) -> Dict[str, str]:
        """Load resiliency pattern definitions."""
        return {
            'circuit_breaker': r'CircuitBreaker|@HystrixCommand|@CircuitBreaker|Resilience4j',
            'retry': r'@Retryable|retry\(',
            'timeout': r'timeout|connectTimeout|readTimeout',
            'bulkhead': r'ThreadPoolExecutor|@EnableAsync.*executor|threadPoolKey',
            'rate_limiting': r'@RateLimiter|RateLimiting|Bucket4j|Guava.*RateLimiter',
            'health_check': r'/health|/actuator|HealthIndicator|@Health',
            'fallback': r'fallback|fallbackMethod|alternative|default'
        }
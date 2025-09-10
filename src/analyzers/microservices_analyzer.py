"""Microservices architecture analyzer."""

import re
import json
from typing import List, Dict, Any, Optional
from .base_analyzer import BaseAnalyzer, AnalysisResult, Issue, Severity, Category


class MicroservicesAnalyzer(BaseAnalyzer):
    """Analyzer for microservices architecture patterns."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.service_patterns = self._load_service_patterns()
        self.api_patterns = self._load_api_patterns()
        self.config_patterns = self._load_config_patterns()
    
    def can_analyze(self, filename: str) -> bool:
        """Check if this analyzer can analyze microservices-related files."""
        microservice_files = [
            '.java', '.py', '.js', '.ts', '.go', '.cs',  # Code files
            '.yml', '.yaml', '.json', '.properties',     # Config files
            'dockerfile', 'docker-compose.yml',          # Container files
            '.tf', '.tfvars'                            # Infrastructure files
        ]
        
        filename_lower = filename.lower()
        return (any(filename_lower.endswith(ext) for ext in microservice_files) or
                'dockerfile' in filename_lower or
                'docker-compose' in filename_lower or
                'k8s' in filename_lower or
                'kubernetes' in filename_lower)
    
    def analyze_file(self, filename: str, content: str, diff: Optional[str] = None) -> AnalysisResult:
        """Analyze a file for microservices patterns."""
        issues = []
        
        try:
            lines = content.split('\n')
            
            # Run different types of analysis based on file type
            if 'service_boundaries' in self.checks:
                issues.extend(self._analyze_service_boundaries(filename, content, lines, diff))
            
            if 'api_design' in self.checks:
                issues.extend(self._analyze_api_design(filename, content, lines, diff))
            
            if 'data_consistency' in self.checks:
                issues.extend(self._analyze_data_consistency(filename, content, lines, diff))
            
            if 'configuration_management' in self.checks:
                issues.extend(self._analyze_configuration(filename, content, lines, diff))
            
            if 'monitoring_observability' in self.checks:
                issues.extend(self._analyze_monitoring(filename, content, lines, diff))
            
            if 'security_patterns' in self.checks:
                issues.extend(self._analyze_security_patterns(filename, content, lines, diff))
            
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
                title="Analysis Error",
                description=f"Error analyzing microservices patterns: {str(e)}",
                recommendation="Review file structure and content",
                confidence=0.5,
                rule_id="ANALYSIS_ERROR"
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
    
    def _analyze_service_boundaries(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze service boundary patterns."""
        issues = []
        
        # Check for tight coupling indicators
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Direct database access from multiple services
            if re.search(r'@Entity|@Table|CREATE TABLE', line, re.IGNORECASE):
                # Check if this looks like shared database access
                if 'shared' in filename.lower() or 'common' in filename.lower():
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.MAJOR,
                        category=Category.DESIGN,
                        title="Shared Database Anti-pattern",
                        description="Shared database access detected across services",
                        recommendation="Each microservice should own its data. Consider database per service pattern",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.7,
                        rule_id="SHARED_DATABASE"
                    ))
            
            # Synchronous inter-service calls without timeout
            if re.search(r'RestTemplate|WebClient|HttpClient', line) and 'timeout' not in line.lower():
                issues.append(Issue(
                    filename=filename,
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.RELIABILITY,
                    title="Missing Timeout Configuration",
                    description="HTTP client without timeout configuration",
                    recommendation="Configure timeouts for all inter-service calls to prevent cascading failures",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="MISSING_TIMEOUT"
                ))
            
            # Large service indicator (too many endpoints)
            if re.search(r'@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping', line):
                # Count endpoints in the file
                endpoint_count = len(re.findall(r'@(Get|Post|Put|Delete|Request)Mapping', content))
                if endpoint_count > 20:
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.MAJOR,
                        category=Category.DESIGN,
                        title="Service Too Large",
                        description=f"Service has {endpoint_count} endpoints, indicating it may be too large",
                        recommendation="Consider breaking this service into smaller, more focused services",
                        confidence=0.6,
                        rule_id="LARGE_SERVICE"
                    ))
                    break  # Only report once per file
        
        return issues
    
    def _analyze_api_design(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze API design patterns."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Missing API versioning
            if re.search(r'@RequestMapping.*["\']/', line) and not re.search(r'/v\d+/', line):
                issues.append(Issue(
                    filename=filename,
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.DESIGN,
                    title="Missing API Versioning",
                    description="API endpoint without version information",
                    recommendation="Include version information in API paths (e.g., /v1/users)",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.7,
                    rule_id="MISSING_API_VERSION"
                ))
            
            # Non-RESTful endpoint naming
            if re.search(r'@RequestMapping.*["\'].*(get|create|update|delete)', line, re.IGNORECASE):
                issues.append(Issue(
                    filename=filename,
                    line_number=i,
                    column=None,
                    severity=Severity.SUGGESTION,
                    category=Category.DESIGN,
                    title="Non-RESTful Endpoint",
                    description="Endpoint name includes HTTP verb, which is not RESTful",
                    recommendation="Use HTTP methods (GET, POST, PUT, DELETE) instead of including verbs in URLs",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="NON_RESTFUL_ENDPOINT"
                ))
            
            # Missing input validation
            if re.search(r'@PostMapping|@PutMapping', line) and '@Valid' not in content:
                issues.append(Issue(
                    filename=filename,
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.SECURITY,
                    title="Missing Input Validation",
                    description="POST/PUT endpoint without input validation",
                    recommendation="Add @Valid annotation and validation constraints to request bodies",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.6,
                    rule_id="MISSING_VALIDATION"
                ))
        
        return issues
    
    def _analyze_data_consistency(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze data consistency patterns."""
        issues = []
        
        # Check for distributed transaction patterns
        has_transaction = '@Transactional' in content
        has_distributed_calls = bool(re.search(r'RestTemplate|WebClient|@FeignClient', content))
        
        if has_transaction and has_distributed_calls:
            issues.append(Issue(
                filename=filename,
                line_number=1,
                column=None,
                severity=Severity.MAJOR,
                category=Category.RELIABILITY,
                title="Distributed Transaction Anti-pattern",
                description="Local transaction with distributed service calls detected",
                recommendation="Consider using Saga pattern or eventual consistency instead of distributed transactions",
                confidence=0.8,
                rule_id="DISTRIBUTED_TRANSACTION"
            ))
        
        # Check for event sourcing patterns
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Missing idempotency for critical operations
            if re.search(r'@PostMapping.*/(payment|order|transfer)', line, re.IGNORECASE):
                if 'idempotent' not in content.lower() and 'idempotency' not in content.lower():
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.MAJOR,
                        category=Category.RELIABILITY,
                        title="Missing Idempotency",
                        description="Critical operation without idempotency handling",
                        recommendation="Implement idempotency keys for critical operations like payments",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.8,
                        rule_id="MISSING_IDEMPOTENCY"
                    ))
        
        return issues
    
    def _analyze_configuration(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze configuration management."""
        issues = []
        
        # Check configuration files
        if filename.endswith(('.yml', '.yaml', '.properties', '.json')):
            for i, line in enumerate(lines, 1):
                if diff and not self._is_in_diff(i, diff):
                    continue
                
                # Hardcoded secrets in config
                if re.search(r'(password|secret|key|token):\s*["\']?[^"\'\s]+', line, re.IGNORECASE):
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.CRITICAL,
                        category=Category.SECURITY,
                        title="Hardcoded Secret in Config",
                        description="Hardcoded secret detected in configuration file",
                        recommendation="Use environment variables or secret management systems",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.9,
                        rule_id="HARDCODED_SECRET_CONFIG"
                    ))
                
                # Missing environment-specific configuration
                if 'localhost' in line or '127.0.0.1' in line:
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.MINOR,
                        category=Category.MAINTAINABILITY,
                        title="Hardcoded Localhost",
                        description="Hardcoded localhost address in configuration",
                        recommendation="Use environment-specific configuration or service discovery",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.8,
                        rule_id="HARDCODED_LOCALHOST"
                    ))
        
        return issues
    
    def _analyze_monitoring(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze monitoring and observability patterns."""
        issues = []
        
        # Check for missing health checks
        if filename.endswith('.java') and '@RestController' in content:
            if '/health' not in content and '/actuator' not in content:
                issues.append(Issue(
                    filename=filename,
                    line_number=1,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.RELIABILITY,
                    title="Missing Health Check",
                    description="Service without health check endpoint",
                    recommendation="Implement health check endpoints for service monitoring",
                    confidence=0.7,
                    rule_id="MISSING_HEALTH_CHECK"
                ))
        
        # Check for missing distributed tracing
        has_http_calls = bool(re.search(r'RestTemplate|WebClient|@FeignClient', content))
        has_tracing = bool(re.search(r'@Trace|Tracer|TraceContext', content))
        
        if has_http_calls and not has_tracing:
            issues.append(Issue(
                filename=filename,
                line_number=1,
                column=None,
                severity=Severity.SUGGESTION,
                category=Category.MAINTAINABILITY,
                title="Missing Distributed Tracing",
                description="Service makes HTTP calls but lacks distributed tracing",
                recommendation="Add distributed tracing (Zipkin, Jaeger) for better observability",
                confidence=0.6,
                rule_id="MISSING_TRACING"
            ))
        
        return issues
    
    def _analyze_security_patterns(self, filename: str, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze security patterns in microservices."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Missing authentication/authorization
            if re.search(r'@RequestMapping|@GetMapping|@PostMapping', line):
                if '@PreAuthorize' not in content and '@Secured' not in content and '@RolesAllowed' not in content:
                    issues.append(Issue(
                        filename=filename,
                        line_number=i,
                        column=None,
                        severity=Severity.MAJOR,
                        category=Category.SECURITY,
                        title="Missing Authorization",
                        description="Endpoint without authorization checks",
                        recommendation="Add appropriate authorization annotations (@PreAuthorize, @Secured)",
                        code_snippet=self._extract_code_snippet(content, i),
                        confidence=0.7,
                        rule_id="MISSING_AUTHORIZATION"
                    ))
            
            # Insecure inter-service communication
            if re.search(r'http://.*:\d+', line):
                issues.append(Issue(
                    filename=filename,
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.SECURITY,
                    title="Insecure HTTP Communication",
                    description="Using HTTP instead of HTTPS for service communication",
                    recommendation="Use HTTPS for all inter-service communication",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.9,
                    rule_id="INSECURE_HTTP"
                ))
        
        return issues
    
    def _calculate_confidence(self, filename: str, content: str, issues: List[Issue]) -> float:
        """Calculate confidence score for the analysis."""
        base_confidence = 0.7
        
        # Higher confidence for known microservice files
        if any(pattern in filename.lower() for pattern in ['service', 'controller', 'api']):
            base_confidence += 0.1
        
        # Higher confidence if Spring Boot patterns detected
        if '@SpringBootApplication' in content or '@RestController' in content:
            base_confidence += 0.1
        
        # Lower confidence for config files (harder to analyze)
        if filename.endswith(('.yml', '.yaml', '.json', '.properties')):
            base_confidence -= 0.1
        
        return min(1.0, max(0.1, base_confidence))
    
    def _generate_metrics(self, filename: str, content: str, issues: List[Issue]) -> Dict[str, Any]:
        """Generate microservices-specific metrics."""
        lines = content.split('\n')
        
        metrics = {
            'total_lines': len(lines),
            'issues_found': len(issues),
            'security_issues': len([i for i in issues if i.category == Category.SECURITY]),
            'design_issues': len([i for i in issues if i.category == Category.DESIGN]),
            'reliability_issues': len([i for i in issues if i.category == Category.RELIABILITY])
        }
        
        # Count microservice-specific patterns
        metrics.update({
            'rest_endpoints': len(re.findall(r'@(Get|Post|Put|Delete|Request)Mapping', content)),
            'http_clients': len(re.findall(r'RestTemplate|WebClient|@FeignClient', content)),
            'database_entities': len(re.findall(r'@Entity|@Table', content)),
            'transaction_boundaries': content.count('@Transactional'),
            'security_annotations': len(re.findall(r'@(PreAuthorize|Secured|RolesAllowed)', content))
        })
        
        return metrics
    
    def _load_service_patterns(self) -> Dict[str, str]:
        """Load service boundary patterns."""
        return {
            'shared_database': r'@Entity|@Table|CREATE TABLE',
            'http_client': r'RestTemplate|WebClient|HttpClient',
            'rest_endpoint': r'@RequestMapping|@GetMapping|@PostMapping'
        }
    
    def _load_api_patterns(self) -> Dict[str, str]:
        """Load API design patterns."""
        return {
            'api_versioning': r'/v\d+/',
            'restful_naming': r'@RequestMapping.*["\'].*(get|create|update|delete)',
            'input_validation': r'@Valid'
        }
    
    def _load_config_patterns(self) -> Dict[str, str]:
        """Load configuration patterns."""
        return {
            'hardcoded_secret': r'(password|secret|key|token):\s*["\']?[^"\'\s]+',
            'localhost': r'localhost|127\.0\.0\.1',
            'environment_variable': r'\$\{[^}]+\}'
        }
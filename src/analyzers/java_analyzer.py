"""Java code analyzer for security, performance, and best practices."""

import re
import javalang
from typing import List, Dict, Any, Optional
from .base_analyzer import BaseAnalyzer, AnalysisResult, Issue, Severity, Category


class JavaAnalyzer(BaseAnalyzer):
    """Analyzer for Java code."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.security_patterns = self._load_security_patterns()
        self.performance_patterns = self._load_performance_patterns()
        self.design_patterns = self._load_design_patterns()
    
    def can_analyze(self, filename: str) -> bool:
        """Check if this analyzer can analyze Java files."""
        return filename.endswith('.java')
    
    def analyze_file(self, filename: str, content: str, diff: Optional[str] = None) -> AnalysisResult:
        """Analyze a Java file for various issues."""
        issues = []
        
        try:
            # Parse Java code
            tree = javalang.parse.parse(content)
            lines = content.split('\n')
            
            # Run different types of analysis
            if 'security_vulnerabilities' in self.checks:
                issues.extend(self._analyze_security(content, lines, diff))
            
            if 'performance_issues' in self.checks:
                issues.extend(self._analyze_performance(content, lines, tree, diff))
            
            if 'design_patterns' in self.checks:
                issues.extend(self._analyze_design_patterns(content, lines, tree, diff))
            
            if 'exception_handling' in self.checks:
                issues.extend(self._analyze_exception_handling(content, lines, tree, diff))
            
            if 'thread_safety' in self.checks:
                issues.extend(self._analyze_thread_safety(content, lines, tree, diff))
            
            if 'spring_boot_best_practices' in self.checks:
                issues.extend(self._analyze_spring_boot(content, lines, diff))
            
            if 'microservices_patterns' in self.checks:
                issues.extend(self._analyze_microservices_patterns(content, lines, diff))
            
            # Calculate confidence score
            confidence = self._calculate_confidence(content, issues)
            
            # Generate metrics
            metrics = self._generate_metrics(content, tree, issues)
            
        except javalang.parser.JavaSyntaxError as e:
            # Handle syntax errors
            issues.append(Issue(
                filename=filename,
                line_number=getattr(e, 'at', 1),
                column=None,
                severity=Severity.CRITICAL,
                category=Category.RELIABILITY,
                title="Java Syntax Error",
                description=f"Syntax error in Java code: {str(e)}",
                recommendation="Fix the syntax error to ensure code compiles correctly.",
                confidence=1.0,
                rule_id="JAVA_SYNTAX_ERROR"
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
    
    def _analyze_security(self, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze for security vulnerabilities."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # SQL Injection: detect either direct execute with concatenation or concatenated SQL assignment
            if (
                re.search(r'Statement.*execute(Query|Update)\s*\(\s*["\'].*\+.*["\']', line)
                or re.search(r'=\s*["\']\s*(SELECT|UPDATE|DELETE|INSERT)\b.*\+.*["\']?\s*;', line, re.IGNORECASE)
            ):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    title="Potential SQL Injection",
                    description="String concatenation used to construct SQL queries",
                    recommendation="Use PreparedStatement with parameterized queries instead",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.9,
                    rule_id="SQL_INJECTION"
                ))
            
            # Hardcoded passwords/secrets
            if re.search(r'(password|secret|key|token)\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.SECURITY,
                    title="Hardcoded Secret",
                    description="Hardcoded password or secret detected",
                    recommendation="Use environment variables or secure configuration management",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="HARDCODED_SECRET"
                ))
            
            # Insecure random number generation
            if 'new Random()' in line or 'Math.random()' in line:
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.SECURITY,
                    title="Insecure Random Number Generation",
                    description="Using insecure random number generator",
                    recommendation="Use SecureRandom for cryptographic purposes",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.7,
                    rule_id="INSECURE_RANDOM"
                ))
            
            # Deserialization vulnerabilities
            if re.search(r'ObjectInputStream.*readObject', line):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    title="Unsafe Deserialization",
                    description="Unsafe object deserialization detected",
                    recommendation="Validate and sanitize input before deserialization, or use safer alternatives",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="UNSAFE_DESERIALIZATION"
                ))
        
        return issues
    
    def _analyze_performance(self, content: str, lines: List[str], tree, diff: Optional[str]) -> List[Issue]:
        """Analyze for performance issues."""
        issues = []
        
        has_for_loop = 'for (' in content or re.search(r'for\s*\(', content) is not None
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # String concatenation in loops (heuristic): detect "+=" concatenation when there's a for-loop in file
            if has_for_loop and re.search(r'\b\w+\s*\+=\s*[^;]*\+', line):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.PERFORMANCE,
                    title="String Concatenation in Loop",
                    description="String concatenation likely inside a loop can cause performance issues",
                    recommendation="Use StringBuilder or StringBuffer for string concatenation in loops",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="STRING_CONCAT_LOOP"
                ))
            
            # Inefficient collection operations
            if re.search(r'\.contains\s*\(.*\)\s*&&.*\.remove\s*\(', line):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.PERFORMANCE,
                    title="Inefficient Collection Operation",
                    description="Calling contains() before remove() is inefficient",
                    recommendation="Use remove() directly as it returns boolean indicating success",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.7,
                    rule_id="INEFFICIENT_COLLECTION_OP"
                ))
            
            # Boxing in loops
            if re.search(r'for.*Integer.*=.*new Integer', line):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.PERFORMANCE,
                    title="Boxing in Loop",
                    description="Unnecessary boxing in loop can impact performance",
                    recommendation="Use primitive types or Integer.valueOf() for better performance",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="BOXING_IN_LOOP"
                ))
        
        return issues
    
    def _analyze_design_patterns(self, content: str, lines: List[str], tree, diff: Optional[str]) -> List[Issue]:
        """Analyze design patterns and architecture."""
        issues = []
        
        # Check for God class (too many methods/fields)
        try:
            for path, node in tree:
                if isinstance(node, javalang.tree.ClassDeclaration):
                    method_count = len([n for n in node.body if isinstance(n, javalang.tree.MethodDeclaration)])
                    field_count = len([n for n in node.body if isinstance(n, javalang.tree.FieldDeclaration)])
                    
                    if method_count > 20:
                        issues.append(Issue(
                            filename="",
                            line_number=1,  # Class declaration line
                            column=None,
                            severity=Severity.MAJOR,
                            category=Category.DESIGN,
                            title="God Class Detected",
                            description=f"Class has {method_count} methods, which may indicate it has too many responsibilities",
                            recommendation="Consider breaking this class into smaller, more focused classes",
                            confidence=0.7,
                            rule_id="GOD_CLASS"
                        ))
                    
                    if field_count > 15:
                        issues.append(Issue(
                            filename="",
                            line_number=1,
                            column=None,
                            severity=Severity.MINOR,
                            category=Category.DESIGN,
                            title="Too Many Fields",
                            description=f"Class has {field_count} fields, which may indicate poor encapsulation",
                            recommendation="Consider using composition or breaking into smaller classes",
                            confidence=0.6,
                            rule_id="TOO_MANY_FIELDS"
                        ))
        except Exception:
            pass  # Skip if AST analysis fails
        
        return issues
    
    def _analyze_exception_handling(self, content: str, lines: List[str], tree, diff: Optional[str]) -> List[Issue]:
        """Analyze exception handling patterns."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Empty catch blocks
            if re.search(r'catch\s*\([^)]+\)\s*\{\s*\}', line):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.RELIABILITY,
                    title="Empty Catch Block",
                    description="Empty catch block swallows exceptions",
                    recommendation="Handle the exception appropriately or at least log it",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.9,
                    rule_id="EMPTY_CATCH"
                ))
            
            # Generic exception catching
            if re.search(r'catch\s*\(\s*Exception\s+', line):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.RELIABILITY,
                    title="Generic Exception Caught",
                    description="Catching generic Exception is too broad",
                    recommendation="Catch specific exception types for better error handling",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.7,
                    rule_id="GENERIC_EXCEPTION"
                ))
        
        return issues
    
    def _analyze_thread_safety(self, content: str, lines: List[str], tree, diff: Optional[str]) -> List[Issue]:
        """Analyze thread safety issues."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Unsynchronized access to shared mutable state
            if re.search(r'static.*(?!final).*=', line) and 'volatile' not in line and 'synchronized' not in line:
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.RELIABILITY,
                    title="Potential Thread Safety Issue",
                    description="Static mutable field without proper synchronization",
                    recommendation="Use volatile, synchronized, or concurrent collections for thread safety",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.6,
                    rule_id="THREAD_SAFETY"
                ))
        
        return issues
    
    def _analyze_spring_boot(self, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze Spring Boot specific patterns."""
        issues = []
        
        has_spring_imports = any('@' in line and ('Component' in line or 'Service' in line or 'Controller' in line) 
                                for line in lines)
        
        if not has_spring_imports:
            return issues
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Missing @Transactional on service methods
            if '@Service' in content and 'save' in line.lower() and '@Transactional' not in content:
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.RELIABILITY,
                    title="Missing @Transactional",
                    description="Service method performing database operations should be transactional",
                    recommendation="Add @Transactional annotation to ensure data consistency",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.6,
                    rule_id="MISSING_TRANSACTIONAL"
                ))
            
            # Field injection instead of constructor injection
            if re.search(r'@Autowired.*private.*[A-Z]', line):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.SUGGESTION,
                    category=Category.DESIGN,
                    title="Field Injection Used",
                    description="Field injection makes testing harder and creates tight coupling",
                    recommendation="Use constructor injection for better testability and immutability",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="FIELD_INJECTION"
                ))
        
        return issues
    
    def _analyze_microservices_patterns(self, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze microservices-specific patterns."""
        issues = []
        
        # Check for circuit breaker pattern usage
        has_rest_template = 'RestTemplate' in content or 'WebClient' in content
        has_circuit_breaker = 'CircuitBreaker' in content or '@HystrixCommand' in content
        
        if has_rest_template and not has_circuit_breaker:
            issues.append(Issue(
                filename="",
                line_number=1,
                column=None,
                severity=Severity.MINOR,
                category=Category.RELIABILITY,
                title="Missing Circuit Breaker",
                description="HTTP client calls should implement circuit breaker pattern",
                recommendation="Add circuit breaker (Hystrix, Resilience4j) for better fault tolerance",
                confidence=0.6,
                rule_id="MISSING_CIRCUIT_BREAKER"
            ))
        
        return issues
    
    def _calculate_confidence(self, content: str, issues: List[Issue]) -> float:
        """Calculate confidence score for the analysis."""
        base_confidence = 0.8
        
        # Reduce confidence if file is very large (harder to analyze accurately)
        line_count = len(content.split('\n'))
        if line_count > 1000:
            base_confidence -= 0.1
        
        # Reduce confidence if there are syntax errors
        syntax_errors = [i for i in issues if i.rule_id == "JAVA_SYNTAX_ERROR"]
        if syntax_errors:
            base_confidence -= 0.3
        
        return max(0.1, base_confidence)
    
    def _generate_metrics(self, content: str, tree, issues: List[Issue]) -> Dict[str, Any]:
        """Generate code metrics."""
        lines = content.split('\n')
        
        metrics = {
            'lines_of_code': len([line for line in lines if line.strip() and not line.strip().startswith('//')]),
            'total_lines': len(lines),
            'comment_lines': len([line for line in lines if line.strip().startswith('//')]),
            'blank_lines': len([line for line in lines if not line.strip()]),
            'issues_found': len(issues),
            'security_issues': len([i for i in issues if i.category == Category.SECURITY]),
            'performance_issues': len([i for i in issues if i.category == Category.PERFORMANCE])
        }
        
        try:
            # AST-based metrics
            class_count = 0
            method_count = 0
            
            for path, node in tree:
                if isinstance(node, javalang.tree.ClassDeclaration):
                    class_count += 1
                elif isinstance(node, javalang.tree.MethodDeclaration):
                    method_count += 1
            
            metrics.update({
                'class_count': class_count,
                'method_count': method_count,
                'avg_methods_per_class': method_count / class_count if class_count > 0 else 0
            })
        except Exception:
            pass  # Skip AST metrics if parsing fails
        
        return metrics
    
    def _load_security_patterns(self) -> Dict[str, Any]:
        """Load security vulnerability patterns."""
        return {
            'sql_injection': r'Statement.*executeQuery\s*\(\s*["\'].*\+.*["\']',
            'hardcoded_secrets': r'(password|secret|key|token)\s*=\s*["\'][^"\']+["\']',
            'insecure_random': r'new Random\(\)|Math\.random\(\)',
            'unsafe_deserialization': r'ObjectInputStream.*readObject'
        }
    
    def _load_performance_patterns(self) -> Dict[str, Any]:
        """Load performance anti-patterns."""
        return {
            'string_concat_loop': r'for\s*\(.*\)\s*\{.*\+.*String',
            'inefficient_collection': r'\.contains\s*\(.*\)\s*&&.*\.remove\s*\(',
            'boxing_in_loop': r'for.*Integer.*=.*new Integer'
        }
    
    def _load_design_patterns(self) -> Dict[str, Any]:
        """Load design pattern checks."""
        return {
            'god_class_methods': 20,
            'god_class_fields': 15,
            'max_method_length': 50,
            'max_parameter_count': 5
        }
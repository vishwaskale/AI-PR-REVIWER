"""SQL code analyzer for performance, security, and best practices."""

import re
import sqlparse
from sqlparse import sql, tokens
from typing import List, Dict, Any, Optional
from .base_analyzer import BaseAnalyzer, AnalysisResult, Issue, Severity, Category


class SQLAnalyzer(BaseAnalyzer):
    """Analyzer for SQL code."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.databases = config.get('databases', ['postgresql', 'mysql'])
        self.performance_patterns = self._load_performance_patterns()
        self.security_patterns = self._load_security_patterns()
    
    def can_analyze(self, filename: str) -> bool:
        """Check if this analyzer can analyze SQL files."""
        sql_extensions = ['.sql', '.ddl', '.dml']
        return any(filename.lower().endswith(ext) for ext in sql_extensions)
    
    def analyze_file(self, filename: str, content: str, diff: Optional[str] = None) -> AnalysisResult:
        """Analyze a SQL file for various issues."""
        issues = []
        
        try:
            # Parse SQL content
            parsed = sqlparse.parse(content)
            lines = content.split('\n')
            
            # Run different types of analysis
            if 'query_performance' in self.checks:
                issues.extend(self._analyze_performance(content, lines, parsed, diff))
            
            if 'sql_injection_prevention' in self.checks:
                issues.extend(self._analyze_security(content, lines, diff))
            
            if 'index_usage' in self.checks:
                issues.extend(self._analyze_index_usage(content, lines, parsed, diff))
            
            if 'join_optimization' in self.checks:
                issues.extend(self._analyze_joins(content, lines, parsed, diff))
            
            if 'data_type_usage' in self.checks:
                issues.extend(self._analyze_data_types(content, lines, parsed, diff))
            
            if 'transaction_handling' in self.checks:
                issues.extend(self._analyze_transactions(content, lines, diff))
            
            if 'stored_procedure_quality' in self.checks:
                issues.extend(self._analyze_stored_procedures(content, lines, parsed, diff))
            
            # Calculate confidence score
            confidence = self._calculate_confidence(content, parsed, issues)
            
            # Generate metrics
            metrics = self._generate_metrics(content, parsed, issues)
            
        except Exception as e:
            # Handle parsing errors
            issues.append(Issue(
                filename=filename,
                line_number=1,
                column=None,
                severity=Severity.CRITICAL,
                category=Category.RELIABILITY,
                title="SQL Parsing Error",
                description=f"Error parsing SQL content: {str(e)}",
                recommendation="Check SQL syntax and ensure it's valid SQL.",
                confidence=1.0,
                rule_id="SQL_PARSE_ERROR"
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
    
    def _analyze_performance(self, content: str, lines: List[str], parsed, diff: Optional[str]) -> List[Issue]:
        """Analyze for performance issues."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            line_upper = line.upper().strip()
            
            # SELECT * usage
            if re.search(r'SELECT\s+\*\s+FROM', line_upper):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.PERFORMANCE,
                    title="SELECT * Usage",
                    description="Using SELECT * can impact performance and maintainability",
                    recommendation="Specify only the columns you need instead of using SELECT *",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="SELECT_STAR"
                ))
            
            # Missing WHERE clause in UPDATE/DELETE
            if re.search(r'(UPDATE|DELETE)\s+(?!.*WHERE)', line_upper):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.CRITICAL,
                    category=Category.RELIABILITY,
                    title="Missing WHERE Clause",
                    description="UPDATE/DELETE without WHERE clause affects all rows",
                    recommendation="Always include a WHERE clause to limit the scope of UPDATE/DELETE operations",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.9,
                    rule_id="MISSING_WHERE"
                ))
            
            # LIKE with leading wildcard
            if re.search(r"LIKE\s+['\"]%", line_upper):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.PERFORMANCE,
                    title="Leading Wildcard in LIKE",
                    description="LIKE with leading wildcard prevents index usage",
                    recommendation="Avoid leading wildcards in LIKE patterns or consider full-text search",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="LEADING_WILDCARD"
                ))
            
            # Functions in WHERE clause
            if re.search(r'WHERE\s+\w+\s*\([^)]*\)\s*[=<>]', line_upper):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.PERFORMANCE,
                    title="Function in WHERE Clause",
                    description="Functions in WHERE clause can prevent index usage",
                    recommendation="Consider restructuring the query to avoid functions on indexed columns",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.7,
                    rule_id="FUNCTION_IN_WHERE"
                ))
            
            # ORDER BY without LIMIT
            if 'ORDER BY' in line_upper and 'LIMIT' not in content.upper():
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.PERFORMANCE,
                    title="ORDER BY without LIMIT",
                    description="ORDER BY without LIMIT can be expensive for large result sets",
                    recommendation="Consider adding LIMIT clause if you don't need all results",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.6,
                    rule_id="ORDER_WITHOUT_LIMIT"
                ))
        
        return issues
    
    def _analyze_security(self, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze for security vulnerabilities."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Dynamic SQL construction (potential SQL injection)
            if re.search(r'(EXEC|EXECUTE)\s*\(\s*[\'"].*\+.*[\'"]', line, re.IGNORECASE):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    title="Potential SQL Injection",
                    description="Dynamic SQL construction detected",
                    recommendation="Use parameterized queries or stored procedures with parameters",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.9,
                    rule_id="SQL_INJECTION"
                ))
            
            # Hardcoded passwords in SQL
            if re.search(r'(PASSWORD|PWD)\s*=\s*[\'"][^\'"]+[\'"]', line, re.IGNORECASE):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.SECURITY,
                    title="Hardcoded Password",
                    description="Hardcoded password detected in SQL",
                    recommendation="Use environment variables or secure configuration for passwords",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="HARDCODED_PASSWORD"
                ))
            
            # Overly permissive GRANT statements
            if re.search(r'GRANT\s+ALL\s+PRIVILEGES', line, re.IGNORECASE):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.SECURITY,
                    title="Overly Permissive Grant",
                    description="GRANT ALL PRIVILEGES gives excessive permissions",
                    recommendation="Grant only the minimum required privileges",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="EXCESSIVE_PRIVILEGES"
                ))
        
        return issues
    
    def _analyze_index_usage(self, content: str, lines: List[str], parsed, diff: Optional[str]) -> List[Issue]:
        """Analyze index usage patterns."""
        issues = []
        
        # Check for missing indexes on foreign keys
        create_table_pattern = re.compile(r'CREATE\s+TABLE\s+(\w+)', re.IGNORECASE)
        foreign_key_pattern = re.compile(r'FOREIGN\s+KEY\s*\([^)]+\)\s+REFERENCES\s+(\w+)', re.IGNORECASE)
        
        current_table = None
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            table_match = create_table_pattern.search(line)
            if table_match:
                current_table = table_match.group(1)
            
            fk_match = foreign_key_pattern.search(line)
            if fk_match and current_table:
                # This is a simplified check - in practice, you'd want to track
                # if indexes are actually created for these foreign keys
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.SUGGESTION,
                    category=Category.PERFORMANCE,
                    title="Consider Index on Foreign Key",
                    description=f"Foreign key reference to {fk_match.group(1)} may benefit from an index",
                    recommendation="Consider creating an index on the foreign key column for better join performance",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.6,
                    rule_id="FK_INDEX_SUGGESTION"
                ))
        
        return issues
    
    def _analyze_joins(self, content: str, lines: List[str], parsed, diff: Optional[str]) -> List[Issue]:
        """Analyze JOIN patterns."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            line_upper = line.upper()
            
            # Cartesian product (missing JOIN condition)
            if re.search(r'FROM\s+\w+\s*,\s*\w+', line_upper) and 'WHERE' not in content.upper():
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MAJOR,
                    category=Category.PERFORMANCE,
                    title="Potential Cartesian Product",
                    description="Multiple tables in FROM clause without proper JOIN conditions",
                    recommendation="Use explicit JOIN syntax with proper ON conditions",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.7,
                    rule_id="CARTESIAN_PRODUCT"
                ))
            
            # Implicit joins (old style)
            if re.search(r'FROM\s+\w+\s*,\s*\w+.*WHERE.*=', line_upper):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.MAINTAINABILITY,
                    title="Implicit JOIN Syntax",
                    description="Using old-style implicit JOIN syntax",
                    recommendation="Use explicit JOIN syntax for better readability",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="IMPLICIT_JOIN"
                ))
        
        return issues
    
    def _analyze_data_types(self, content: str, lines: List[str], parsed, diff: Optional[str]) -> List[Issue]:
        """Analyze data type usage."""
        issues = []
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            line_upper = line.upper()
            
            # VARCHAR without length specification
            if re.search(r'VARCHAR\s*(?!\()', line_upper):
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.RELIABILITY,
                    title="VARCHAR without Length",
                    description="VARCHAR without explicit length specification",
                    recommendation="Always specify length for VARCHAR columns",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.8,
                    rule_id="VARCHAR_NO_LENGTH"
                ))
            
            # Using TEXT for short strings
            if 'TEXT' in line_upper and 'CREATE TABLE' in content.upper():
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.SUGGESTION,
                    category=Category.PERFORMANCE,
                    title="TEXT Type Usage",
                    description="TEXT type may be overkill for short strings",
                    recommendation="Consider using VARCHAR with appropriate length for better performance",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.6,
                    rule_id="TEXT_OVERUSE"
                ))
        
        return issues
    
    def _analyze_transactions(self, content: str, lines: List[str], diff: Optional[str]) -> List[Issue]:
        """Analyze transaction handling."""
        issues = []
        
        has_begin = 'BEGIN' in content.upper() or 'START TRANSACTION' in content.upper()
        has_commit = 'COMMIT' in content.upper()
        has_rollback = 'ROLLBACK' in content.upper()
        
        if has_begin and not has_commit:
            issues.append(Issue(
                filename="",
                line_number=1,
                column=None,
                severity=Severity.MAJOR,
                category=Category.RELIABILITY,
                title="Missing COMMIT",
                description="Transaction started but no COMMIT found",
                recommendation="Ensure all transactions are properly committed or rolled back",
                confidence=0.8,
                rule_id="MISSING_COMMIT"
            ))
        
        if has_begin and not has_rollback:
            issues.append(Issue(
                filename="",
                line_number=1,
                column=None,
                severity=Severity.SUGGESTION,
                category=Category.RELIABILITY,
                title="No Error Handling",
                description="Transaction without error handling (ROLLBACK)",
                recommendation="Consider adding error handling with ROLLBACK for transaction safety",
                confidence=0.6,
                rule_id="NO_ERROR_HANDLING"
            ))
        
        return issues
    
    def _analyze_stored_procedures(self, content: str, lines: List[str], parsed, diff: Optional[str]) -> List[Issue]:
        """Analyze stored procedure quality."""
        issues = []
        
        if 'CREATE PROCEDURE' not in content.upper() and 'CREATE FUNCTION' not in content.upper():
            return issues
        
        for i, line in enumerate(lines, 1):
            if diff and not self._is_in_diff(i, diff):
                continue
            
            # Missing error handling in stored procedures
            if 'CREATE PROCEDURE' in line.upper() and 'TRY' not in content.upper():
                issues.append(Issue(
                    filename="",
                    line_number=i,
                    column=None,
                    severity=Severity.MINOR,
                    category=Category.RELIABILITY,
                    title="Missing Error Handling",
                    description="Stored procedure without error handling",
                    recommendation="Add TRY-CATCH blocks for proper error handling",
                    code_snippet=self._extract_code_snippet(content, i),
                    confidence=0.7,
                    rule_id="SP_NO_ERROR_HANDLING"
                ))
        
        return issues
    
    def _calculate_confidence(self, content: str, parsed, issues: List[Issue]) -> float:
        """Calculate confidence score for the analysis."""
        base_confidence = 0.8
        
        # Reduce confidence if parsing failed
        if not parsed:
            base_confidence -= 0.3
        
        # Reduce confidence for very large files
        line_count = len(content.split('\n'))
        if line_count > 500:
            base_confidence -= 0.1
        
        # Reduce confidence if there are parsing errors
        parse_errors = [i for i in issues if i.rule_id == "SQL_PARSE_ERROR"]
        if parse_errors:
            base_confidence -= 0.3
        
        return max(0.1, base_confidence)
    
    def _generate_metrics(self, content: str, parsed, issues: List[Issue]) -> Dict[str, Any]:
        """Generate SQL metrics."""
        lines = content.split('\n')
        
        metrics = {
            'total_lines': len(lines),
            'non_empty_lines': len([line for line in lines if line.strip()]),
            'comment_lines': len([line for line in lines if line.strip().startswith('--')]),
            'issues_found': len(issues),
            'security_issues': len([i for i in issues if i.category == Category.SECURITY]),
            'performance_issues': len([i for i in issues if i.category == Category.PERFORMANCE])
        }
        
        # Count SQL statement types
        content_upper = content.upper()
        metrics.update({
            'select_statements': content_upper.count('SELECT'),
            'insert_statements': content_upper.count('INSERT'),
            'update_statements': content_upper.count('UPDATE'),
            'delete_statements': content_upper.count('DELETE'),
            'create_statements': content_upper.count('CREATE'),
            'alter_statements': content_upper.count('ALTER'),
            'drop_statements': content_upper.count('DROP')
        })
        
        return metrics
    
    def _load_performance_patterns(self) -> Dict[str, str]:
        """Load performance anti-patterns."""
        return {
            'select_star': r'SELECT\s+\*\s+FROM',
            'missing_where': r'(UPDATE|DELETE)\s+(?!.*WHERE)',
            'leading_wildcard': r"LIKE\s+['\"]%",
            'function_in_where': r'WHERE\s+\w+\s*\([^)]*\)\s*[=<>]'
        }
    
    def _load_security_patterns(self) -> Dict[str, str]:
        """Load security vulnerability patterns."""
        return {
            'sql_injection': r'(EXEC|EXECUTE)\s*\(\s*[\'"].*\+.*[\'"]',
            'hardcoded_password': r'(PASSWORD|PWD)\s*=\s*[\'"][^\'"]+[\'"]',
            'excessive_privileges': r'GRANT\s+ALL\s+PRIVILEGES'
        }
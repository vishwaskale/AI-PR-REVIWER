"""Base analyzer class for code analysis."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from enum import Enum


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    SUGGESTION = "suggestion"


class Category(Enum):
    """Issue categories."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"
    RELIABILITY = "reliability"
    DESIGN = "design"
    STYLE = "style"
    DOCUMENTATION = "documentation"
    TESTING = "testing"


@dataclass
class Issue:
    """Represents a code issue found during analysis."""
    
    filename: str
    line_number: int
    column: Optional[int]
    severity: Severity
    category: Category
    title: str
    description: str
    recommendation: str
    code_snippet: Optional[str] = None
    confidence: float = 1.0
    rule_id: Optional[str] = None


@dataclass
class AnalysisResult:
    """Results of code analysis."""
    
    issues: List[Issue]
    confidence_score: float
    summary: Dict[str, Any]
    metrics: Dict[str, Any]
    
    def get_issues_by_severity(self, severity: Severity) -> List[Issue]:
        """Get issues filtered by severity."""
        return [issue for issue in self.issues if issue.severity == severity]
    
    def get_issues_by_category(self, category: Category) -> List[Issue]:
        """Get issues filtered by category."""
        return [issue for issue in self.issues if issue.category == category]
    
    def has_critical_issues(self) -> bool:
        """Check if there are any critical issues."""
        return len(self.get_issues_by_severity(Severity.CRITICAL)) > 0
    
    def has_security_issues(self) -> bool:
        """Check if there are any security issues."""
        return len(self.get_issues_by_category(Category.SECURITY)) > 0


class BaseAnalyzer(ABC):
    """Base class for all code analyzers."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.checks = config.get('checks', [])
        self.severity_levels = config.get('severity_levels', ['critical', 'major', 'minor', 'suggestion'])
    
    @abstractmethod
    def can_analyze(self, filename: str) -> bool:
        """Check if this analyzer can analyze the given file."""
        pass
    
    @abstractmethod
    def analyze_file(self, filename: str, content: str, diff: Optional[str] = None) -> AnalysisResult:
        """Analyze a single file and return issues."""
        pass
    
    def analyze_files(self, files: Dict[str, str], diffs: Optional[Dict[str, str]] = None) -> AnalysisResult:
        """Analyze multiple files and combine results."""
        all_issues = []
        total_confidence = 0.0
        file_count = 0
        combined_metrics = {}
        
        for filename, content in files.items():
            if not self.can_analyze(filename):
                continue
                
            diff = diffs.get(filename) if diffs else None
            result = self.analyze_file(filename, content, diff)
            
            all_issues.extend(result.issues)
            total_confidence += result.confidence_score
            file_count += 1
            
            # Combine metrics
            for key, value in result.metrics.items():
                if key in combined_metrics:
                    if isinstance(value, (int, float)):
                        combined_metrics[key] += value
                    elif isinstance(value, list):
                        combined_metrics[key].extend(value)
                else:
                    combined_metrics[key] = value
        
        avg_confidence = total_confidence / file_count if file_count > 0 else 0.0
        
        summary = self._generate_summary(all_issues)
        
        return AnalysisResult(
            issues=all_issues,
            confidence_score=avg_confidence,
            summary=summary,
            metrics=combined_metrics
        )
    
    def _generate_summary(self, issues: List[Issue]) -> Dict[str, Any]:
        """Generate summary statistics from issues."""
        summary = {
            'total_issues': len(issues),
            'by_severity': {},
            'by_category': {},
            'critical_issues': 0,
            'security_issues': 0,
            'performance_issues': 0
        }
        
        for issue in issues:
            # Count by severity
            severity_key = issue.severity.value
            summary['by_severity'][severity_key] = summary['by_severity'].get(severity_key, 0) + 1
            
            # Count by category
            category_key = issue.category.value
            summary['by_category'][category_key] = summary['by_category'].get(category_key, 0) + 1
            
            # Special counters
            if issue.severity == Severity.CRITICAL:
                summary['critical_issues'] += 1
            if issue.category == Category.SECURITY:
                summary['security_issues'] += 1
            if issue.category == Category.PERFORMANCE:
                summary['performance_issues'] += 1
        
        return summary
    
    def _extract_code_snippet(self, content: str, line_number: int, context_lines: int = 3) -> str:
        """Extract code snippet around the specified line."""
        lines = content.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            snippet_lines.append(f"{prefix}{i + 1:4d}: {lines[i]}")
        
        return '\n'.join(snippet_lines)
    
    def _is_in_diff(self, line_number: int, diff: str) -> bool:
        """Check if a line number is part of the diff (changed code)."""
        if not diff:
            return True  # If no diff provided, assume all lines are relevant
        
        # Simple heuristic: look for line numbers in diff format
        # This is a simplified implementation - in practice, you'd want
        # a more robust diff parser
        lines = diff.split('\n')
        for line in lines:
            if line.startswith('@@'):
                # Parse hunk header like @@ -10,7 +10,6 @@
                try:
                    parts = line.split(' ')
                    if len(parts) >= 3:
                        new_range = parts[2]  # +10,6
                        if new_range.startswith('+'):
                            start_line = int(new_range[1:].split(',')[0])
                            if ',' in new_range:
                                line_count = int(new_range.split(',')[1])
                            else:
                                line_count = 1
                            
                            if start_line <= line_number <= start_line + line_count:
                                return True
                except (ValueError, IndexError):
                    continue
        
        return False
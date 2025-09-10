"""Main review engine that orchestrates the code analysis and review process."""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from .config import Config
from .bitbucket_client import BitbucketClient, PullRequest, FileChange, ReviewComment
from .ai_service import AIService, AIAnalysisRequest
from .analyzers import (
    JavaAnalyzer, SQLAnalyzer, MicroservicesAnalyzer, ResiliencyAnalyzer,
    AnalysisResult, Issue, Severity, Category
)

logger = logging.getLogger(__name__)


@dataclass
class ReviewResult:
    """Result of PR review."""
    pr_id: int
    repository: str
    total_files: int
    analyzed_files: int
    total_issues: int
    critical_issues: int
    security_issues: int
    performance_issues: int
    recommendation: str  # approve, request_changes, comment
    confidence: float
    summary: str
    file_results: List[Dict[str, Any]]


class ReviewEngine:
    """Main engine for pull request review."""
    
    def __init__(self, config: Config):
        self.config = config
        self.bitbucket_client = BitbucketClient(
            username=config.bitbucket.username,
            app_password=config.bitbucket.app_password,
            workspace=config.bitbucket.workspace,
            base_url=config.bitbucket.base_url
        )
        
        # Initialize AI service
        if config.ai.provider == 'openai':
            self.ai_service = AIService('openai', config.ai.openai_api_key, config.ai.openai_model)
        elif config.ai.provider == 'anthropic':
            self.ai_service = AIService('anthropic', config.ai.anthropic_api_key, config.ai.anthropic_model)
        else:
            raise ValueError(f"Unsupported AI provider: {config.ai.provider}")
        
        # Initialize analyzers
        self.analyzers = self._initialize_analyzers()
    
    def _initialize_analyzers(self) -> List:
        """Initialize code analyzers based on configuration."""
        analyzers = []
        
        java_config = self.config.get_review_rules('java')
        if java_config.get('enabled', False):
            analyzers.append(JavaAnalyzer(java_config))
        
        sql_config = self.config.get_review_rules('sql')
        if sql_config.get('enabled', False):
            analyzers.append(SQLAnalyzer(sql_config))
        
        microservices_config = self.config.get_review_rules('microservices')
        if microservices_config.get('enabled', False):
            analyzers.append(MicroservicesAnalyzer(microservices_config))
        
        resiliency_config = self.config.get_review_rules('resiliency')
        if resiliency_config.get('enabled', False):
            analyzers.append(ResiliencyAnalyzer(resiliency_config))
        
        return analyzers
    
    async def review_pull_request(self, repository: str, pr_id: int) -> ReviewResult:
        """Review a pull request and provide feedback."""
        logger.info(f"Starting review of PR {pr_id} in {repository}")
        
        try:
            # Get PR information
            pr = self.bitbucket_client.get_pull_request(repository, pr_id)
            if not pr:
                raise ValueError(f"Could not fetch PR {pr_id}")
            
            # Get changed files
            files = self.bitbucket_client.get_pull_request_files(repository, pr_id)
            if len(files) > self.config.review.max_files_per_pr:
                logger.warning(f"PR has {len(files)} files, limiting to {self.config.review.max_files_per_pr}")
                files = files[:self.config.review.max_files_per_pr]
            
            # Get diff for context
            diff = self.bitbucket_client.get_pull_request_diff(repository, pr_id)
            
            # Analyze files
            file_results = []
            total_issues = 0
            critical_issues = 0
            security_issues = 0
            performance_issues = 0
            
            for file_change in files:
                if file_change.status == 'removed':
                    continue
                
                result = await self._analyze_file(repository, pr, file_change, diff)
                if result:
                    file_results.append(result)
                    total_issues += result['total_issues']
                    critical_issues += result['critical_issues']
                    security_issues += result['security_issues']
                    performance_issues += result['performance_issues']
            
            # Calculate overall confidence
            avg_confidence = sum(r['confidence'] for r in file_results) / len(file_results) if file_results else 0.0
            
            # Determine recommendation
            recommendation = self._determine_recommendation(
                critical_issues, security_issues, performance_issues, avg_confidence
            )
            
            # Generate summary
            summary = await self._generate_summary(pr, file_results, total_issues, critical_issues)
            
            # Post review comments
            await self._post_review_comments(repository, pr_id, file_results)
            
            # Take action based on recommendation
            await self._take_action(repository, pr_id, recommendation, summary)
            
            review_result = ReviewResult(
                pr_id=pr_id,
                repository=repository,
                total_files=len(files),
                analyzed_files=len(file_results),
                total_issues=total_issues,
                critical_issues=critical_issues,
                security_issues=security_issues,
                performance_issues=performance_issues,
                recommendation=recommendation,
                confidence=avg_confidence,
                summary=summary,
                file_results=file_results
            )
            
            logger.info(f"Completed review of PR {pr_id}: {recommendation}")
            return review_result
            
        except Exception as e:
            logger.error(f"Error reviewing PR {pr_id}: {e}")
            raise
    
    async def _analyze_file(self, repository: str, pr: PullRequest, 
                          file_change: FileChange, diff: Optional[str]) -> Optional[Dict[str, Any]]:
        """Analyze a single file."""
        try:
            # Get file content
            commits = self.bitbucket_client.get_pull_request_commits(repository, pr.id)
            if not commits:
                logger.warning(f"No commits found for PR {pr.id}")
                return None
            
            latest_commit = commits[0]['hash']
            content = self.bitbucket_client.get_file_content(repository, latest_commit, file_change.filename)
            
            if not content:
                logger.warning(f"Could not fetch content for {file_change.filename}")
                return None
            
            if len(content.split('\n')) > self.config.review.max_lines_per_file:
                logger.warning(f"File {file_change.filename} too large, skipping")
                return None
            
            # Find applicable analyzers
            applicable_analyzers = [a for a in self.analyzers if a.can_analyze(file_change.filename)]
            
            if not applicable_analyzers:
                logger.debug(f"No analyzers for {file_change.filename}")
                return None
            
            # Run static analysis
            static_results = []
            for analyzer in applicable_analyzers:
                result = analyzer.analyze_file(file_change.filename, content, diff)
                static_results.append(result)
            
            # Combine static analysis results
            combined_issues = []
            for result in static_results:
                combined_issues.extend(result.issues)
            
            # Run AI analysis for additional insights
            ai_request = AIAnalysisRequest(
                filename=file_change.filename,
                content=content,
                diff=self._extract_file_diff(diff, file_change.filename),
                language=self._detect_language(file_change.filename),
                context={
                    'pr_title': pr.title,
                    'pr_description': pr.description,
                    'file_status': file_change.status,
                    'additions': file_change.additions,
                    'deletions': file_change.deletions
                }
            )
            
            ai_response = await self.ai_service.analyze_code(ai_request)
            
            # Convert AI issues to our format
            ai_issues = []
            for ai_issue in ai_response.issues:
                issue = Issue(
                    filename=file_change.filename,
                    line_number=ai_issue.get('line_number', 1),
                    column=None,
                    severity=Severity(ai_issue.get('severity', 'minor')),
                    category=Category(ai_issue.get('category', 'maintainability')),
                    title=ai_issue.get('title', 'AI-detected issue'),
                    description=ai_issue.get('description', ''),
                    recommendation=ai_issue.get('recommendation', ''),
                    confidence=ai_issue.get('confidence', 0.5),
                    rule_id=f"AI_{ai_issue.get('category', 'general').upper()}"
                )
                ai_issues.append(issue)
            
            # Combine all issues
            all_issues = combined_issues + ai_issues
            
            # Calculate metrics
            total_issues = len(all_issues)
            critical_issues = len([i for i in all_issues if i.severity == Severity.CRITICAL])
            security_issues = len([i for i in all_issues if i.category == Category.SECURITY])
            performance_issues = len([i for i in all_issues if i.category == Category.PERFORMANCE])
            
            # Calculate confidence (weighted average)
            static_confidence = sum(r.confidence_score for r in static_results) / len(static_results) if static_results else 0.0
            ai_confidence = ai_response.confidence
            combined_confidence = (static_confidence * 0.6 + ai_confidence * 0.4)
            
            return {
                'filename': file_change.filename,
                'language': self._detect_language(file_change.filename),
                'total_issues': total_issues,
                'critical_issues': critical_issues,
                'security_issues': security_issues,
                'performance_issues': performance_issues,
                'confidence': combined_confidence,
                'issues': all_issues,
                'ai_summary': ai_response.summary,
                'ai_recommendations': ai_response.recommendations,
                'static_results': static_results
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_change.filename}: {e}")
            return None
    
    def _extract_file_diff(self, full_diff: Optional[str], filename: str) -> Optional[str]:
        """Extract diff for a specific file."""
        if not full_diff:
            return None
        
        # Simple extraction - in practice, you'd want a proper diff parser
        lines = full_diff.split('\n')
        file_diff_lines = []
        in_file = False
        
        for line in lines:
            if line.startswith(f'diff --git a/{filename}'):
                in_file = True
                file_diff_lines.append(line)
            elif line.startswith('diff --git') and in_file:
                break
            elif in_file:
                file_diff_lines.append(line)
        
        return '\n'.join(file_diff_lines) if file_diff_lines else None
    
    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename."""
        extension_map = {
            '.java': 'java',
            '.sql': 'sql',
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.go': 'go',
            '.cs': 'csharp',
            '.yml': 'yaml',
            '.yaml': 'yaml',
            '.json': 'json',
            '.properties': 'properties'
        }
        
        for ext, lang in extension_map.items():
            if filename.lower().endswith(ext):
                return lang
        
        return 'text'
    
    def _determine_recommendation(self, critical_issues: int, security_issues: int, 
                                performance_issues: int, confidence: float) -> str:
        """Determine review recommendation."""
        # Auto-reject conditions
        if critical_issues > 0 or security_issues > 2:
            return 'request_changes'
        
        # Auto-approve conditions
        if (critical_issues == 0 and security_issues == 0 and 
            performance_issues <= 1 and confidence >= self.config.review.auto_approve_threshold):
            return 'approve'
        
        # Request changes for significant issues
        if security_issues > 0 or performance_issues > 3:
            return 'request_changes'
        
        # Default to comment
        return 'comment'
    
    async def _generate_summary(self, pr: PullRequest, file_results: List[Dict[str, Any]], 
                              total_issues: int, critical_issues: int) -> str:
        """Generate overall PR summary."""
        pr_info = {
            'title': pr.title,
            'author': pr.author,
            'source_branch': pr.source_branch,
            'destination_branch': pr.destination_branch
        }
        
        return await self.ai_service.generate_pr_summary(file_results, pr_info)
    
    async def _post_review_comments(self, repository: str, pr_id: int, 
                                  file_results: List[Dict[str, Any]]) -> None:
        """Post review comments for issues found."""
        for file_result in file_results:
            filename = file_result['filename']
            language = file_result['language']
            
            for issue in file_result['issues']:
                # Skip low-confidence suggestions
                if issue.confidence < self.config.review.confidence_threshold:
                    continue
                
                # Get appropriate comment template
                template = self.config.get_comment_template(language, issue.category.value)
                
                # Generate comment using AI
                comment_text = await self.ai_service.generate_review_comment(
                    {
                        'title': issue.title,
                        'description': issue.description,
                        'recommendation': issue.recommendation,
                        'severity': issue.severity.value,
                        'category': issue.category.value,
                        'confidence': issue.confidence
                    },
                    template
                )
                
                # Post comment
                success = self.bitbucket_client.add_pull_request_comment(
                    repository=repository,
                    pr_id=pr_id,
                    content=comment_text,
                    filename=filename,
                    line_number=issue.line_number
                )
                
                if not success:
                    logger.warning(f"Failed to post comment for {filename}:{issue.line_number}")
    
    async def _take_action(self, repository: str, pr_id: int, 
                         recommendation: str, summary: str) -> None:
        """Take action based on recommendation."""
        # Post summary comment
        self.bitbucket_client.add_pull_request_comment(
            repository=repository,
            pr_id=pr_id,
            content=f"## AI Code Review Summary\n\n{summary}"
        )
        
        # Take appropriate action
        if recommendation == 'approve':
            success = self.bitbucket_client.approve_pull_request(repository, pr_id)
            if success:
                logger.info(f"Approved PR {pr_id}")
            else:
                logger.warning(f"Failed to approve PR {pr_id}")
        
        elif recommendation == 'request_changes':
            success = self.bitbucket_client.request_changes(repository, pr_id)
            if success:
                logger.info(f"Requested changes for PR {pr_id}")
            else:
                logger.warning(f"Failed to request changes for PR {pr_id}")
        
        # For 'comment', we just post comments without approval/rejection
        logger.info(f"Posted review comments for PR {pr_id}")
    
    async def review_multiple_prs(self, repository: str) -> List[ReviewResult]:
        """Review all open pull requests in a repository."""
        prs = self.bitbucket_client.list_open_pull_requests(repository)
        results = []
        
        for pr in prs:
            try:
                result = await self.review_pull_request(repository, pr.id)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to review PR {pr.id}: {e}")
        
        return results
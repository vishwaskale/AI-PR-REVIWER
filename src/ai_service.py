"""AI service integration for code analysis and review generation."""

import openai
import anthropic
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class AIAnalysisRequest:
    """Request for AI analysis."""
    filename: str
    content: str
    diff: Optional[str]
    language: str
    context: Dict[str, Any]


@dataclass
class AIAnalysisResponse:
    """Response from AI analysis."""
    issues: List[Dict[str, Any]]
    summary: str
    confidence: float
    recommendations: List[str]


class AIService:
    """Service for AI-powered code analysis."""
    
    def __init__(self, provider: str, api_key: str, model: str):
        self.provider = provider.lower()
        self.model = model
        
        if self.provider == 'openai':
            openai.api_key = api_key
            self.client = openai
        elif self.provider == 'anthropic':
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            raise ValueError(f"Unsupported AI provider: {provider}")
    
    async def analyze_code(self, request: AIAnalysisRequest) -> AIAnalysisResponse:
        """Analyze code using AI."""
        try:
            prompt = self._build_analysis_prompt(request)
            
            if self.provider == 'openai':
                response = await self._call_openai(prompt)
            elif self.provider == 'anthropic':
                response = await self._call_anthropic(prompt)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
            
            return self._parse_ai_response(response)
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return AIAnalysisResponse(
                issues=[],
                summary=f"AI analysis failed: {str(e)}",
                confidence=0.0,
                recommendations=[]
            )
    
    def _build_analysis_prompt(self, request: AIAnalysisRequest) -> str:
        """Build analysis prompt for AI."""
        prompt = f"""
You are an expert code reviewer specializing in {request.language} and microservices architecture.
Please analyze the following code for:

1. Security vulnerabilities
2. Performance issues
3. Design patterns and best practices
4. Microservices patterns
5. Resiliency patterns
6. Code quality and maintainability

File: {request.filename}
Language: {request.language}

Code:
```{request.language}
{request.content}
```
"""
        
        if request.diff:
            prompt += f"""
Diff (focus on changed lines):
```diff
{request.diff}
```
"""
        
        if request.context:
            prompt += f"""
Additional Context:
{json.dumps(request.context, indent=2)}
"""
        
        prompt += """
Please provide your analysis in the following JSON format:
{
    "issues": [
        {
            "line_number": <number>,
            "severity": "critical|major|minor|suggestion",
            "category": "security|performance|maintainability|reliability|design|style",
            "title": "<short title>",
            "description": "<detailed description>",
            "recommendation": "<how to fix>",
            "confidence": <0.0-1.0>
        }
    ],
    "summary": "<overall assessment>",
    "confidence": <0.0-1.0>,
    "recommendations": ["<general recommendations>"]
}

Focus on:
- Security vulnerabilities (SQL injection, XSS, hardcoded secrets)
- Performance anti-patterns (N+1 queries, inefficient algorithms)
- Microservices best practices (service boundaries, API design)
- Resiliency patterns (circuit breakers, retries, timeouts)
- Code quality (maintainability, readability, testability)
"""
        
        return prompt
    
    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API."""
        try:
            response = await self.client.ChatCompletion.acreate(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert code reviewer with deep knowledge of software engineering best practices, security, performance optimization, and microservices architecture."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=2000
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise
    
    async def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude API."""
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                temperature=0.1,
                system="You are an expert code reviewer with deep knowledge of software engineering best practices, security, performance optimization, and microservices architecture.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic API call failed: {e}")
            raise
    
    def _parse_ai_response(self, response: str) -> AIAnalysisResponse:
        """Parse AI response into structured format."""
        try:
            # Extract JSON from response (handle cases where AI adds extra text)
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start == -1 or json_end == 0:
                raise ValueError("No JSON found in response")
            
            json_str = response[json_start:json_end]
            data = json.loads(json_str)
            
            return AIAnalysisResponse(
                issues=data.get('issues', []),
                summary=data.get('summary', 'No summary provided'),
                confidence=data.get('confidence', 0.5),
                recommendations=data.get('recommendations', [])
            )
            
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse AI response: {e}")
            return AIAnalysisResponse(
                issues=[],
                summary=f"Failed to parse AI response: {response[:200]}...",
                confidence=0.0,
                recommendations=[]
            )
    
    async def generate_review_comment(self, issue: Dict[str, Any], template: str) -> str:
        """Generate a formatted review comment for an issue."""
        try:
            prompt = f"""
Generate a professional, constructive code review comment based on this issue:

Issue: {json.dumps(issue, indent=2)}
Template: {template}

The comment should be:
1. Professional and constructive
2. Specific and actionable
3. Include code examples if helpful
4. Explain the "why" behind the recommendation

Generate only the comment text, no additional formatting.
"""
            
            if self.provider == 'openai':
                response = await self.client.ChatCompletion.acreate(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a senior software engineer providing constructive code review feedback."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.3,
                    max_tokens=500
                )
                return response.choices[0].message.content.strip()
            
            elif self.provider == 'anthropic':
                response = await self.client.messages.create(
                    model=self.model,
                    max_tokens=500,
                    temperature=0.3,
                    system="You are a senior software engineer providing constructive code review feedback.",
                    messages=[
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                )
                return response.content[0].text.strip()
            
        except Exception as e:
            logger.error(f"Failed to generate review comment: {e}")
            # Fallback to template-based comment
            return template.format(
                issue_description=issue.get('description', 'Issue detected'),
                recommendation=issue.get('recommendation', 'Please review'),
                severity=issue.get('severity', 'unknown')
            )
    
    async def generate_pr_summary(self, analysis_results: List[Dict[str, Any]], 
                                pr_info: Dict[str, Any]) -> str:
        """Generate overall PR review summary."""
        try:
            total_issues = sum(len(result.get('issues', [])) for result in analysis_results)
            critical_issues = sum(len([i for i in result.get('issues', []) 
                                     if i.get('severity') == 'critical']) 
                                for result in analysis_results)
            
            prompt = f"""
Generate a comprehensive pull request review summary based on the analysis results:

PR Information:
- Title: {pr_info.get('title', 'N/A')}
- Author: {pr_info.get('author', 'N/A')}
- Files changed: {len(analysis_results)}
- Total issues found: {total_issues}
- Critical issues: {critical_issues}

Analysis Results:
{json.dumps(analysis_results, indent=2)}

Generate a professional summary that includes:
1. Overall assessment
2. Key findings and concerns
3. Recommendations for improvement
4. Approval/rejection recommendation with reasoning

Keep it concise but comprehensive.
"""
            
            if self.provider == 'openai':
                response = await self.client.ChatCompletion.acreate(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a senior technical lead reviewing pull requests."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.2,
                    max_tokens=800
                )
                return response.choices[0].message.content
            
            elif self.provider == 'anthropic':
                response = await self.client.messages.create(
                    model=self.model,
                    max_tokens=800,
                    temperature=0.2,
                    system="You are a senior technical lead reviewing pull requests.",
                    messages=[
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                )
                return response.content[0].text
            
        except Exception as e:
            logger.error(f"Failed to generate PR summary: {e}")
            return f"PR Review Summary\n\nTotal files analyzed: {len(analysis_results)}\nTotal issues found: {total_issues}\nCritical issues: {critical_issues}\n\nPlease review the individual file comments for detailed feedback."
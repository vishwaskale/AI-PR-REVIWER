"""Configuration management for the AI PR Reviewer."""

import os
import yaml
from typing import Dict, Any, Optional
from pydantic import Field
try:
    from pydantic_settings import BaseSettings
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "pydantic-settings is required for Pydantic v2. "
        "Install it with: pip install pydantic-settings>=2.0"
    ) from exc
from dotenv import load_dotenv

load_dotenv()


class BitbucketConfig(BaseSettings):
    """Bitbucket API configuration."""
    
    username: str = Field(..., env="BITBUCKET_USERNAME")
    app_password: str = Field(..., env="BITBUCKET_APP_PASSWORD")
    workspace: str = Field(..., env="BITBUCKET_WORKSPACE")
    base_url: str = Field(default="https://api.bitbucket.org/2.0", env="BITBUCKET_BASE_URL")


class AIConfig(BaseSettings):
    """AI provider configuration."""
    
    provider: str = Field(default="openai", env="AI_PROVIDER")
    openai_api_key: Optional[str] = Field(None, env="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4-turbo-preview", env="OPENAI_MODEL")
    anthropic_api_key: Optional[str] = Field(None, env="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-3-sonnet-20240229", env="ANTHROPIC_MODEL")


class ReviewConfig(BaseSettings):
    """Review process configuration."""
    
    max_files_per_pr: int = Field(default=50, env="MAX_FILES_PER_PR")
    max_lines_per_file: int = Field(default=1000, env="MAX_LINES_PER_FILE")
    confidence_threshold: float = Field(default=0.7, env="REVIEW_CONFIDENCE_THRESHOLD")
    auto_approve_threshold: float = Field(default=0.9, env="AUTO_APPROVE_THRESHOLD")
    auto_reject_threshold: float = Field(default=0.3, env="AUTO_REJECT_THRESHOLD")


class LoggingConfig(BaseSettings):
    """Logging configuration."""
    
    level: str = Field(default="INFO", env="LOG_LEVEL")
    file: str = Field(default="pr_reviewer.log", env="LOG_FILE")


class Config:
    """Main configuration class."""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.bitbucket = BitbucketConfig()
        self.ai = AIConfig()
        self.review = ReviewConfig()
        self.logging = LoggingConfig()
        
        # Load YAML configuration
        self.rules = self._load_yaml_config(config_file)
    
    def _load_yaml_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Warning: Config file {config_file} not found. Using defaults.")
            return {}
        except yaml.YAMLError as e:
            print(f"Error parsing config file {config_file}: {e}")
            return {}
    
    def get_review_rules(self, language: str) -> Dict[str, Any]:
        """Get review rules for a specific language."""
        return self.rules.get("review_rules", {}).get(language, {})
    
    def get_comment_template(self, language: str, category: str) -> str:
        """Get comment template for a specific language and category."""
        templates = self.rules.get("comment_templates", {})
        return templates.get(language, {}).get(category, "**{category}**: {issue_description}")
    
    def should_auto_approve(self, analysis_result: Dict[str, Any]) -> bool:
        """Determine if PR should be auto-approved based on analysis."""
        criteria = self.rules.get("approval_criteria", {}).get("auto_approve", {})
        conditions = criteria.get("conditions", {})
        
        # Check confidence score
        confidence_threshold = float(conditions.get("confidence_score", "0.9").replace(">= ", ""))
        if analysis_result.get("confidence_score", 0) < confidence_threshold:
            return False
        
        # Check for critical issues
        if conditions.get("no_critical_issues", True):
            if analysis_result.get("critical_issues", 0) > 0:
                return False
        
        # Check for security issues
        if conditions.get("no_major_security_issues", True):
            if analysis_result.get("security_issues", 0) > 0:
                return False
        
        return True
    
    def should_auto_reject(self, analysis_result: Dict[str, Any]) -> bool:
        """Determine if PR should be auto-rejected based on analysis."""
        criteria = self.rules.get("approval_criteria", {}).get("auto_reject", {})
        conditions = criteria.get("conditions", {})
        
        # Check confidence score
        confidence_threshold = float(conditions.get("confidence_score", "0.3").replace("<= ", ""))
        if analysis_result.get("confidence_score", 1) <= confidence_threshold:
            return True
        
        # Check for critical security vulnerabilities
        if conditions.get("critical_security_vulnerabilities", False):
            if analysis_result.get("critical_security_issues", 0) > 0:
                return True
        
        # Check for major performance regressions
        if conditions.get("major_performance_regressions", False):
            if analysis_result.get("performance_regressions", 0) > 0:
                return True
        
        return False
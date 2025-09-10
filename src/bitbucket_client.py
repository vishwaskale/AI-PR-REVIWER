"""Bitbucket API client for pull request operations."""

import requests
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)


@dataclass
class PullRequest:
    """Pull request data structure."""
    id: int
    title: str
    description: str
    source_branch: str
    destination_branch: str
    author: str
    state: str
    repository: str
    workspace: str
    links: Dict[str, Any]


@dataclass
class FileChange:
    """File change data structure."""
    filename: str
    status: str  # added, modified, removed
    additions: int
    deletions: int
    patch: Optional[str] = None
    old_content: Optional[str] = None
    new_content: Optional[str] = None


@dataclass
class ReviewComment:
    """Review comment data structure."""
    filename: str
    line_number: int
    content: str
    severity: str
    category: str
    inline: bool = True


class BitbucketClient:
    """Bitbucket API client."""
    
    def __init__(self, username: str, app_password: str, workspace: str, base_url: str = "https://api.bitbucket.org/2.0"):
        self.username = username
        self.app_password = app_password
        self.workspace = workspace
        self.base_url = base_url
        self.session = requests.Session()
        self.session.auth = (username, app_password)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def get_pull_request(self, repository: str, pr_id: int) -> Optional[PullRequest]:
        """Get pull request details."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}/pullrequests/{pr_id}"
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            return PullRequest(
                id=data['id'],
                title=data['title'],
                description=data.get('description', ''),
                source_branch=data['source']['branch']['name'],
                destination_branch=data['destination']['branch']['name'],
                author=data['author']['display_name'],
                state=data['state'],
                repository=repository,
                workspace=self.workspace,
                links=data['links']
            )
        except requests.RequestException as e:
            logger.error(f"Error fetching PR {pr_id}: {e}")
            return None
    
    def get_pull_request_diff(self, repository: str, pr_id: int) -> Optional[str]:
        """Get pull request diff."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}/pullrequests/{pr_id}/diff"
            response = self.session.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Error fetching PR diff {pr_id}: {e}")
            return None
    
    def get_pull_request_files(self, repository: str, pr_id: int) -> List[FileChange]:
        """Get list of changed files in pull request."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}/pullrequests/{pr_id}/diffstat"
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            files = []
            
            for file_data in data.get('values', []):
                file_change = FileChange(
                    filename=file_data['old']['path'] if file_data.get('old') else file_data['new']['path'],
                    status=file_data['status'],
                    additions=file_data['lines_added'],
                    deletions=file_data['lines_removed']
                )
                files.append(file_change)
            
            return files
        except requests.RequestException as e:
            logger.error(f"Error fetching PR files {pr_id}: {e}")
            return []
    
    def get_file_content(self, repository: str, commit_hash: str, filepath: str) -> Optional[str]:
        """Get file content at specific commit."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}/src/{commit_hash}/{filepath}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Error fetching file content {filepath} at {commit_hash}: {e}")
            return None
    
    def add_pull_request_comment(self, repository: str, pr_id: int, content: str, 
                               filename: Optional[str] = None, line_number: Optional[int] = None) -> bool:
        """Add a comment to pull request."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}/pullrequests/{pr_id}/comments"
            
            comment_data = {
                'content': {
                    'raw': content
                }
            }
            
            # Add inline comment data if provided
            if filename and line_number:
                comment_data['inline'] = {
                    'to': line_number,
                    'path': filename
                }
            
            response = self.session.post(url, json=comment_data)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.error(f"Error adding comment to PR {pr_id}: {e}")
            return False
    
    def approve_pull_request(self, repository: str, pr_id: int) -> bool:
        """Approve pull request."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}/pullrequests/{pr_id}/approve"
            response = self.session.post(url)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.error(f"Error approving PR {pr_id}: {e}")
            return False
    
    def request_changes(self, repository: str, pr_id: int) -> bool:
        """Request changes on pull request."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}/pullrequests/{pr_id}/request-changes"
            response = self.session.post(url)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.error(f"Error requesting changes on PR {pr_id}: {e}")
            return False
    
    def get_pull_request_commits(self, repository: str, pr_id: int) -> List[Dict[str, Any]]:
        """Get commits in pull request."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}/pullrequests/{pr_id}/commits"
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            return data.get('values', [])
        except requests.RequestException as e:
            logger.error(f"Error fetching PR commits {pr_id}: {e}")
            return []
    
    def get_repository_info(self, repository: str) -> Optional[Dict[str, Any]]:
        """Get repository information."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error fetching repository info {repository}: {e}")
            return None
    
    def list_open_pull_requests(self, repository: str) -> List[PullRequest]:
        """List all open pull requests in repository."""
        try:
            url = f"{self.base_url}/repositories/{self.workspace}/{repository}/pullrequests"
            params = {'state': 'OPEN'}
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            pull_requests = []
            
            for pr_data in data.get('values', []):
                pr = PullRequest(
                    id=pr_data['id'],
                    title=pr_data['title'],
                    description=pr_data.get('description', ''),
                    source_branch=pr_data['source']['branch']['name'],
                    destination_branch=pr_data['destination']['branch']['name'],
                    author=pr_data['author']['display_name'],
                    state=pr_data['state'],
                    repository=repository,
                    workspace=self.workspace,
                    links=pr_data['links']
                )
                pull_requests.append(pr)
            
            return pull_requests
        except requests.RequestException as e:
            logger.error(f"Error listing open PRs for {repository}: {e}")
            return []
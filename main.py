#!/usr/bin/env python3
"""
AI Pull Request Reviewer
A comprehensive AI-powered code review tool for Bitbucket pull requests.

Features:
- Java, SQL, PostgreSQL code analysis
- Microservices architecture patterns
- Resiliency patterns detection
- Security vulnerability scanning
- Performance optimization suggestions
- Automated PR approval/rejection
- Inline code comments
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.cli import cli

if __name__ == '__main__':
    cli()
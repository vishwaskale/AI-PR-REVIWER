# AI Pull Request Reviewer

A comprehensive AI-powered code review tool for Bitbucket that provides intelligent inline comments, security analysis, performance optimization suggestions, and automated PR approval/rejection for Java, SQL, PostgreSQL, microservices, and resiliency patterns.

## Features

### 🔍 **Comprehensive Code Analysis**
- **Java**: Security vulnerabilities, performance issues, design patterns, Spring Boot best practices
- **SQL/PostgreSQL**: Query optimization, security (SQL injection), index usage, transaction handling
- **Microservices**: Service boundaries, API design, data consistency, configuration management
- **Resiliency Patterns**: Circuit breakers, retry mechanisms, timeouts, bulkhead patterns

### 🤖 **AI-Powered Reviews**
- Integration with OpenAI GPT-4 and Anthropic Claude
- Context-aware analysis using diff information
- Natural language explanations and recommendations
- Confidence scoring for all suggestions

### 🔧 **Bitbucket Integration**
- Automated PR discovery and analysis
- Inline code comments on specific lines
- Automated approval/rejection based on configurable criteria
- Support for multiple repositories and workspaces

### 📊 **Advanced Reporting**
- Detailed analysis metrics and statistics
- Security and performance issue categorization
- Confidence scoring and recommendation prioritization
- Rich CLI output with progress indicators

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd ai-pr-reviewer

# Install dependencies
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

### 2. Configuration

Copy the example environment file and configure your settings:

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# Bitbucket Configuration
BITBUCKET_USERNAME=your_username
BITBUCKET_APP_PASSWORD=your_app_password
BITBUCKET_WORKSPACE=your_workspace

# AI Provider (choose one)
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4-turbo-preview

# Or use Anthropic Claude
# AI_PROVIDER=anthropic
# ANTHROPIC_API_KEY=your_anthropic_api_key
# ANTHROPIC_MODEL=claude-3-sonnet-20240229
```

### 3. Test Configuration

```bash
python main.py test-config
```

### 4. Review a Pull Request

```bash
# Review a specific PR
python main.py review my-repo 123

# Analyze without posting comments (dry run)
python main.py analyze my-repo 123

# Review all open PRs in a repository
python main.py review-all my-repo --limit 10
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `BITBUCKET_USERNAME` | Your Bitbucket username | Yes |
| `BITBUCKET_APP_PASSWORD` | Bitbucket app password | Yes |
| `BITBUCKET_WORKSPACE` | Bitbucket workspace name | Yes |
| `AI_PROVIDER` | AI provider (`openai` or `anthropic`) | Yes |
| `OPENAI_API_KEY` | OpenAI API key | If using OpenAI |
| `ANTHROPIC_API_KEY` | Anthropic API key | If using Anthropic |

### Review Rules Configuration

Edit `config.yaml` to customize review rules:

```yaml
review_rules:
  java:
    enabled: true
    checks:
      - security_vulnerabilities
      - performance_issues
      - design_patterns
      - spring_boot_best_practices
      - microservices_patterns
  
  sql:
    enabled: true
    checks:
      - query_performance
      - sql_injection_prevention
      - index_usage
      - join_optimization
  
  microservices:
    enabled: true
    checks:
      - service_boundaries
      - api_design
      - circuit_breaker_patterns
      - monitoring_observability
```

## Usage Examples

### Review a Single PR

```bash
# Basic review (explicit args)
python main.py review my-microservice 456

# Dry run (analyze only, no comments) with explicit args
python main.py analyze my-microservice 456

# Inside Bitbucket (repo/PR auto-detected from env)
python main.py review
# or
python main.py analyze
```

### Batch Review

```bash
# Review all open PRs
python main.py review-all my-microservice

# Limit to 5 PRs
python main.py review-all my-microservice --limit 5

# Inside Bitbucket (repo auto-detected from env)
python main.py review-all --limit 5
```

### Verbose Output

```bash
python main.py --verbose review my-repo 123
```

## Webhook server (FastAPI)

This project can receive Bitbucket pull request webhooks and trigger a review automatically.

1. Install deps (FastAPI and Uvicorn are already in requirements.txt; Uvicorn is installed with `[standard]` extras for better performance and reload)
2. Run the server:

```bash
uvicorn src.server:app --host 0.0.0.0 --port 8000 --reload
```

- `--reload` requires the `watchfiles` extra, which is included via `uvicorn[standard]`.
- For production, omit `--reload` and consider setting workers with a process manager (e.g., systemd, supervisor, or running behind nginx).

3. Configure Bitbucket webhook:
- URL: https://your-host/webhooks/bitbucket
- Events: enable "Pull request created" and "Pull request updated"

4. Security recommendations:
- Restrict inbound IPs on your edge/proxy
- Validate `X-Event-Key` starts with `pullrequest:`
- Optionally add HMAC verification (shared secret)

## Analysis Capabilities

### Java Analysis
- **Security**: SQL injection, hardcoded secrets, insecure random generation, unsafe deserialization
- **Performance**: String concatenation in loops, inefficient collections, boxing issues
- **Design**: God classes, proper exception handling, thread safety
- **Spring Boot**: Missing @Transactional, field vs constructor injection
- **Microservices**: Circuit breaker patterns, service boundaries

### SQL Analysis
- **Performance**: SELECT * usage, missing WHERE clauses, leading wildcards, function usage in WHERE
- **Security**: SQL injection patterns, hardcoded passwords, excessive privileges
- **Optimization**: Index usage suggestions, join optimization, query structure
- **Best Practices**: Transaction handling, stored procedure quality

### Microservices Analysis
- **Architecture**: Service boundaries, shared database anti-patterns, API versioning
- **Resilience**: Circuit breakers, timeout configurations, retry mechanisms
- **Security**: Authentication/authorization, secure communication
- **Configuration**: Environment-specific configs, secret management

### Resiliency Patterns
- **Circuit Breaker**: Implementation detection, fallback methods
- **Retry Logic**: Exponential backoff, maximum attempts
- **Timeouts**: HTTP client timeouts, database operation timeouts
- **Bulkhead**: Thread pool isolation, resource separation
- **Health Checks**: Endpoint availability, dependency monitoring

## Comment Templates

The tool uses configurable comment templates for different issue types:

```yaml
comment_templates:
  java:
    security: "🔒 **Security Issue**: {issue_description}\n\n**Recommendation**: {recommendation}"
    performance: "⚡ **Performance Concern**: {issue_description}\n\n**Suggestion**: {suggestion}"
  
  sql:
    performance: "🐌 **SQL Performance**: {issue_description}\n\n**Optimization**: {optimization}"
```

## Approval Criteria

Configure automatic approval/rejection criteria:

```yaml
approval_criteria:
  auto_approve:
    conditions:
      - no_critical_issues: true
      - no_major_security_issues: true
      - confidence_score: ">= 0.9"
  
  auto_reject:
    conditions:
      - critical_security_vulnerabilities: true
      - confidence_score: "<= 0.3"
```

## API Integration

### Bitbucket Setup

1. Create an App Password in Bitbucket:
   - Go to Bitbucket Settings → App passwords
   - Create new app password with `Repositories: Read` and `Pull requests: Write` permissions

2. Get your workspace name from your Bitbucket URL:
   - `https://bitbucket.org/WORKSPACE_NAME/repository-name`

### AI Provider Setup

#### OpenAI
1. Get API key from [OpenAI Platform](https://platform.openai.com/api-keys)
2. Recommended model: `gpt-4-turbo-preview` or `gpt-4`

#### Anthropic Claude
1. Get API key from [Anthropic Console](https://console.anthropic.com/)
2. Recommended model: `claude-3-sonnet-20240229` or `claude-3-opus-20240229`

## Development

### Project Structure

```
ai-pr-reviewer/
├── src/
│   ├── analyzers/           # Code analyzers for different languages
│   │   ├── java_analyzer.py
│   │   ├── sql_analyzer.py
│   │   ├── microservices_analyzer.py
│   │   └── resiliency_analyzer.py
│   ├── bitbucket_client.py  # Bitbucket API integration
│   ├── ai_service.py        # AI provider integration
│   ├── review_engine.py     # Main review orchestration
│   ├── config.py           # Configuration management
│   └── cli.py              # Command-line interface
├── config.yaml             # Review rules configuration
├── requirements.txt        # Python dependencies
└── main.py                # Entry point
```

### Adding New Analyzers

1. Create a new analyzer class inheriting from `BaseAnalyzer`
2. Implement `can_analyze()` and `analyze_file()` methods
3. Register the analyzer in `ReviewEngine._initialize_analyzers()`

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/
```

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify Bitbucket username and app password
   - Check workspace name is correct
   - Ensure app password has required permissions

2. **AI API Errors**
   - Verify API key is valid and has sufficient credits
   - Check model name is correct
   - Monitor rate limits

3. **Large Files Skipped**
   - Files over 1000 lines are skipped by default
   - Adjust `MAX_LINES_PER_FILE` in configuration

4. **No Comments Posted**
   - Check confidence threshold settings
   - Verify Bitbucket permissions
   - Review dry-run mode settings

### Logging

Enable verbose logging for debugging:

```bash
python main.py --verbose review my-repo 123
```

Logs are also written to `pr_reviewer.log` by default.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue in the GitHub repository
- Check the troubleshooting section
- Review the configuration documentation

---

**Note**: This tool is designed to assist with code reviews, not replace human judgment. Always review AI suggestions before accepting them.
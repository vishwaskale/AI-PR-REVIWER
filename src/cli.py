"""Command-line interface for the AI PR Reviewer."""

import asyncio
import click
import logging
import sys
import os
from pathlib import Path
from typing import List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.logging import RichHandler

from .config import Config
from .review_engine import ReviewEngine, ReviewResult

# Setup rich console
console = Console()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console)]
)
logger = logging.getLogger(__name__)


@click.group()
@click.option('--config', '-c', default='config.yaml', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, config, verbose):
    """AI-powered Pull Request Reviewer for Bitbucket."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    try:
        ctx.ensure_object(dict)
        ctx.obj['config'] = Config(config)
        console.print(f"✅ Loaded configuration from {config}", style="green")
    except Exception as e:
        console.print(f"❌ Failed to load configuration: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.argument('repository', required=False)
@click.argument('pr_id', required=False)
@click.option('--dry-run', is_flag=True, help='Analyze without posting comments')
@click.pass_context
def review(ctx, repository, pr_id, dry_run):
    """Review a specific pull request.
    If running inside Bitbucket Pipelines or a Bitbucket environment, repository and pr_id can be
    inferred from environment variables.
    """
    config = ctx.obj['config']

    # Allow repo/pr inference from environment for Bitbucket
    repo = repository or os.getenv('BITBUCKET_REPO_SLUG') or os.getenv('BITBUCKET_REPOSITORY')
    pr_env = pr_id or os.getenv('BITBUCKET_PR_ID') or os.getenv('PR_ID')
    try:
        pr = int(pr_env) if pr_env is not None else None
    except ValueError:
        pr = None

    if not repo or pr is None:
        console.print("❌ Repository and PR ID are required. Pass as arguments or set BITBUCKET_REPO_SLUG and BITBUCKET_PR_ID.", style="red")
        sys.exit(1)

    console.print(f"🔍 Starting review of PR #{pr} in {repo}")

    if dry_run:
        console.print("🧪 Running in dry-run mode (no comments will be posted)", style="yellow")

    async def run_review():
        try:
            engine = ReviewEngine(config)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Analyzing pull request...", total=None)

                result = await engine.review_pull_request(repo, pr)

                progress.update(task, description="✅ Review completed!")

            # Display results
            _display_review_result(result)

        except Exception as e:
            console.print(f"❌ Review failed: {e}", style="red")
            logger.exception("Review failed")
            sys.exit(1)

    asyncio.run(run_review())


@cli.command()
@click.argument('repository', required=False)
@click.option('--limit', '-l', default=10, help='Maximum number of PRs to review')
@click.pass_context
def review_all(ctx, repository, limit):
    """Review all open pull requests in a repository.
    If running inside Bitbucket, repository can be inferred from BITBUCKET_REPO_SLUG.
    """
    config = ctx.obj['config']

    repo = repository or os.getenv('BITBUCKET_REPO_SLUG') or os.getenv('BITBUCKET_REPOSITORY')
    if not repo:
        console.print("❌ Repository is required. Pass as an argument or set BITBUCKET_REPO_SLUG.", style="red")
        sys.exit(1)

    console.print(f"🔍 Reviewing all open PRs in {repo} (limit: {limit})")

    async def run_review_all():
        try:
            engine = ReviewEngine(config)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Fetching open pull requests...", total=None)

                results = await engine.review_multiple_prs(repo)

                # Limit results
                results = results[:limit]

                progress.update(task, description=f"✅ Reviewed {len(results)} PRs!")

            # Display summary
            _display_multiple_results(results)

        except Exception as e:
            console.print(f"❌ Batch review failed: {e}", style="red")
            logger.exception("Batch review failed")
            sys.exit(1)

    asyncio.run(run_review_all())


@cli.command()
@click.argument('repository', required=False)
@click.argument('pr_id', required=False)
@click.pass_context
def analyze(ctx, repository, pr_id):
    """Analyze a pull request without posting comments (dry run).
    In Bitbucket environments, repository and pr_id can be inferred from env.
    """
    config = ctx.obj['config']

    repo = repository or os.getenv('BITBUCKET_REPO_SLUG') or os.getenv('BITBUCKET_REPOSITORY')
    pr_env = pr_id or os.getenv('BITBUCKET_PR_ID') or os.getenv('PR_ID')
    try:
        pr = int(pr_env) if pr_env is not None else None
    except ValueError:
        pr = None

    if not repo or pr is None:
        console.print("❌ Repository and PR ID are required. Pass as arguments or set BITBUCKET_REPO_SLUG and BITBUCKET_PR_ID.", style="red")
        sys.exit(1)

    console.print(f"🔬 Analyzing PR #{pr} in {repo} (dry run)")

    async def run_analysis():
        try:
            engine = ReviewEngine(config)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Analyzing code...", total=None)

                # Create a modified engine that doesn't post comments
                async def mock_post_comments(*args, **kwargs):
                    pass

                async def mock_take_action(*args, **kwargs):
                    pass

                engine._post_review_comments = mock_post_comments
                engine._take_action = mock_take_action

                result = await engine.review_pull_request(repo, pr)

                progress.update(task, description="✅ Analysis completed!")

            # Display detailed results
            _display_detailed_analysis(result)

        except Exception as e:
            console.print(f"❌ Analysis failed: {e}", style="red")
            logger.exception("Analysis failed")
            sys.exit(1)

    asyncio.run(run_analysis())


@cli.command()
@click.pass_context
def test_config(ctx):
    """Test the configuration and API connections."""
    config = ctx.obj['config']
    
    console.print("🧪 Testing configuration...")
    
    # Test Bitbucket connection
    try:
        from .bitbucket_client import BitbucketClient
        client = BitbucketClient(
            username=config.bitbucket.username,
            app_password=config.bitbucket.app_password,
            workspace=config.bitbucket.workspace,
            base_url=config.bitbucket.base_url
        )
        
        # Try to get workspace info (simple API test)
        response = client.session.get(f"{client.base_url}/workspaces/{client.workspace}")
        if response.status_code == 200:
            console.print("✅ Bitbucket connection successful", style="green")
        else:
            console.print(f"❌ Bitbucket connection failed: {response.status_code}", style="red")
    except Exception as e:
        console.print(f"❌ Bitbucket connection failed: {e}", style="red")
    
    # Test AI service
    try:
        from .ai_service import AIService
        
        if config.ai.provider == 'openai':
            ai_service = AIService('openai', config.ai.openai_api_key, config.ai.openai_model)
        elif config.ai.provider == 'anthropic':
            ai_service = AIService('anthropic', config.ai.anthropic_api_key, config.ai.anthropic_model)
        
        console.print(f"✅ AI service configured: {config.ai.provider} ({config.ai.openai_model if config.ai.provider == 'openai' else config.ai.anthropic_model})", style="green")
    except Exception as e:
        console.print(f"❌ AI service configuration failed: {e}", style="red")
    
    # Test analyzers
    try:
        engine = ReviewEngine(config)
        console.print(f"✅ Initialized {len(engine.analyzers)} code analyzers", style="green")
        
        for analyzer in engine.analyzers:
            console.print(f"  - {analyzer.__class__.__name__}", style="dim")
    except Exception as e:
        console.print(f"❌ Analyzer initialization failed: {e}", style="red")


def _display_review_result(result: ReviewResult):
    """Display review result in a formatted table."""
    console.print("\n📊 Review Results", style="bold blue")
    
    # Summary table
    table = Table(title=f"PR #{result.pr_id} in {result.repository}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Files Analyzed", f"{result.analyzed_files}/{result.total_files}")
    table.add_row("Total Issues", str(result.total_issues))
    table.add_row("Critical Issues", str(result.critical_issues))
    table.add_row("Security Issues", str(result.security_issues))
    table.add_row("Performance Issues", str(result.performance_issues))
    table.add_row("Confidence", f"{result.confidence:.2f}")
    table.add_row("Recommendation", result.recommendation.upper())
    
    console.print(table)
    
    # Summary
    console.print(f"\n📝 Summary:\n{result.summary}")


def _display_multiple_results(results: List[ReviewResult]):
    """Display multiple review results."""
    console.print(f"\n📊 Batch Review Results ({len(results)} PRs)", style="bold blue")
    
    table = Table()
    table.add_column("PR ID", style="cyan")
    table.add_column("Files", style="dim")
    table.add_column("Issues", style="yellow")
    table.add_column("Critical", style="red")
    table.add_column("Security", style="orange1")
    table.add_column("Recommendation", style="green")
    table.add_column("Confidence", style="blue")
    
    for result in results:
        table.add_row(
            str(result.pr_id),
            f"{result.analyzed_files}/{result.total_files}",
            str(result.total_issues),
            str(result.critical_issues),
            str(result.security_issues),
            result.recommendation.upper(),
            f"{result.confidence:.2f}"
        )
    
    console.print(table)
    
    # Summary stats
    total_issues = sum(r.total_issues for r in results)
    total_critical = sum(r.critical_issues for r in results)
    total_security = sum(r.security_issues for r in results)
    avg_confidence = sum(r.confidence for r in results) / len(results) if results else 0
    
    console.print(f"\n📈 Overall Stats:")
    console.print(f"  Total Issues: {total_issues}")
    console.print(f"  Critical Issues: {total_critical}")
    console.print(f"  Security Issues: {total_security}")
    console.print(f"  Average Confidence: {avg_confidence:.2f}")


def _display_detailed_analysis(result: ReviewResult):
    """Display detailed analysis results."""
    _display_review_result(result)
    
    # File-by-file breakdown
    if result.file_results:
        console.print("\n📁 File Analysis Details", style="bold blue")
        
        for file_result in result.file_results:
            console.print(f"\n🔍 {file_result['filename']} ({file_result['language']})")
            console.print(f"  Issues: {file_result['total_issues']} (Critical: {file_result['critical_issues']}, Security: {file_result['security_issues']})")
            console.print(f"  Confidence: {file_result['confidence']:.2f}")
            
            if file_result.get('ai_summary'):
                console.print(f"  AI Summary: {file_result['ai_summary'][:100]}...")
            
            # Show top issues
            issues = file_result.get('issues', [])
            if issues:
                console.print("  Top Issues:")
                for issue in issues[:3]:  # Show top 3 issues
                    severity_color = {
                        'critical': 'red',
                        'major': 'orange1',
                        'minor': 'yellow',
                        'suggestion': 'dim'
                    }.get(issue.severity.value, 'white')
                    
                    console.print(f"    • Line {issue.line_number}: {issue.title}", style=severity_color)


if __name__ == '__main__':
    cli()
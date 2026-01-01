"""Main CLI entry point for Leviathan."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click

from ..utils.logging import setup_logging, get_logger
from ..core.config import get_config, reload_config
from ..core.pipeline import Pipeline, PipelinePhase


@click.group()
@click.option("--config", "config_file", type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--log-level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO", help="Set logging level")
@click.pass_context
def main(ctx: click.Context, config_file: Optional[str], debug: bool, log_level: str) -> None:
    """Leviathan - Security Automation and Analysis Framework"""

    # Set up configuration
    if config_file:
        # Load from file (future implementation)
        pass

    # Update config with CLI options
    from ..core.config import update_config
    update_config({
        "debug": debug,
        "log_level": log_level
    })

    # Set up logging
    setup_logging()

    # Store config in context
    ctx.ensure_object(dict)
    ctx.obj["config"] = get_config()


@main.command()
@click.argument("target")
@click.option("--phases", help="Comma-separated list of phases to run")
@click.option("--output", type=click.Path(), help="Output file for results")
@click.option("--format", type=click.Choice(["json", "yaml", "text"]), default="json",
              help="Output format")
@click.pass_context
def analyze(ctx: click.Context, target: str, phases: Optional[str],
           output: Optional[str], format: str) -> None:
    """Run analysis pipeline on target."""

    config = ctx.obj["config"]
    logger = get_logger("leviathan.cli")

    # Parse phases
    if phases:
        phase_list = [PipelinePhase(p.strip()) for p in phases.split(",")]
    else:
        phase_list = None

    async def run_analysis():
        pipeline = Pipeline()

        # TODO: Register actual modules here
        # For now, just run the pipeline structure

        try:
            results = await pipeline.execute(target, phase_list)

            # Output results
            if output:
                output_path = Path(output)
                # TODO: Format and save results
                logger.info("Results saved", path=str(output_path))
            else:
                # Print to console
                click.echo(f"Analysis completed. Results: {len(results)} modules executed")

        except Exception as e:
            logger.error("Analysis failed", error=str(e))
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await pipeline.shutdown()

    # Run async
    asyncio.run(run_analysis())


@main.command()
@click.pass_context
def modules(ctx: click.Context) -> None:
    """List available modules."""
    pipeline = Pipeline()
    # TODO: List registered modules
    click.echo("Available modules: (none registered yet)")


@main.command()
@click.option("--port", default=8000, help="Port for metrics server")
@click.pass_context
def serve(ctx: click.Context, port: int) -> None:
    """Start metrics server."""
    # TODO: Implement metrics server
    click.echo(f"Metrics server would start on port {port}")


if __name__ == "__main__":
    main()
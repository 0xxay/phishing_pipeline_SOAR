"""Rich console logging for the phishing pipeline."""
import logging
from rich.logging import RichHandler
from rich.console import Console
from datetime import datetime
import config

# Create console
console = Console()

# Create logger
logger = logging.getLogger("phishing_pipeline")
logger.setLevel(config.LOG_LEVEL)

# Create handlers
file_handler = logging.FileHandler(config.LOG_FILE)
file_handler.setLevel(config.LOG_LEVEL)

console_handler = RichHandler(
    console=console,
    show_time=True,
    show_level=True,
    show_path=False,
)
console_handler.setLevel(config.LOG_LEVEL)

# Create formatters
formatter = logging.Formatter(
    fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)


def log_section(title: str):
    """Log a section header."""
    console.print(f"\n[bold cyan]{'=' * 60}[/bold cyan]")
    console.print(f"[bold cyan]{title}[/bold cyan]")
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")


def log_success(message: str):
    """Log a success message."""
    console.print(f"[green]{message}[/green]")
    logger.info(message)


def log_warning(message: str):
    """Log a warning message."""
    console.print(f"[yellow]{message}[/yellow]")
    logger.warning(message)


def log_error(message: str):
    """Log an error message."""
    console.print(f"[red]{message}[/red]")
    logger.error(message)


def log_info(message: str):
    """Log an info message."""
    console.print(f"[white]{message}[/white]")
    logger.info(message)


def log_debug(message: str):
    """Log a debug message."""
    console.print(f"[dim]{message}[/dim]")
    logger.debug(message)


def log_ioc(ioc_type: str, ioc: str, details: str = ""):
    """Log an IOC with details."""
    msg = f"[bold blue]{ioc_type.upper()}[/bold blue]: {ioc}"
    if details:
        msg += f" - {details}"
    console.print(msg)

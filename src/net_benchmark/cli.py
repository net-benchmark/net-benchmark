import os
from typing import Optional

import click
import pyfiglet
from colorama import Fore, Style, init

from net_benchmark import __version__
from net_benchmark.dns_benchmark.cli import dns as dns_group
from net_benchmark.http_bench.cli import http as http_group

# from net_benchmark.ssl_check.cli import ssl as ssl_group

ssl_group: Optional[click.Group] = None

try:
    from net_benchmark.ssl_check.cli import ssl as _ssl  # noqa: F811

    ssl_group = _ssl
except ImportError:
    pass

# Initialize colorama
init()


@click.group()
@click.version_option(__version__, prog_name="net-benchmark")
def cli() -> None:
    """
    net-benchmark — DNS, HTTP, and SSL benchmarking suite.
    CLI entry point.
    """
    # Allow suppression of banner for CI/CD
    if not os.environ.get("NO_BANNER"):
        print(Fore.GREEN + pyfiglet.figlet_format("net-benchmark") + Style.RESET_ALL)
        print(Fore.CYAN + "dns · http · ssl benchmarking suite" + Style.RESET_ALL)
        print(
            Fore.YELLOW
            + "https://github.com/net-benchmark/net-benchmark"
            + Style.RESET_ALL
        )
        print()


cli.add_command(dns_group)
cli.add_command(http_group)
# cli.add_command(ssl_group)
if ssl_group is not None:
    cli.add_command(ssl_group)

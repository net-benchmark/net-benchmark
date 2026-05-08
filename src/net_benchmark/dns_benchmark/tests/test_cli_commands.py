import subprocess
import tempfile
import time
from pathlib import Path

import pytest

WAIT_INTERVAL = 2  # Seconds to wait between commands

DATA_DIR = Path(__file__).parent / "sample_data"
RESOLVERS = DATA_DIR / "resolvers.json"
DOMAINS = DATA_DIR / "domains.txt"

COMMANDS = [
    # Basic quick tests
    f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} "
    # "--formats csv,excel,pdf --domain-stats --record-type-stats --error-breakdown --json --output {{outdir}}", # Heavy test, commented out for regular runs
    # Quick performance test
    f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --output {{outdir}}",
    f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --quiet --output {{outdir}}",
    # Commented out: record type stats and breakdowns
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --record-types A,AAAA,MX --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --domain-stats --record-type-stats --error-breakdown --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --json --output {{outdir}}",
    # New options smoke tests (commented out for speed)
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --iterations 2 --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --iterations 2 --use-cache --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --warmup --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --warmup-fast --output {{outdir}}",
    # Information & discovery (keep lightweight ones)
    "net-benchmark dns list-defaults",
    "net-benchmark dns list-resolvers",
    # "net-benchmark dns list-resolvers --details", # Slower
    "net-benchmark dns list-resolvers --category security",
    "net-benchmark dns list-resolvers --category privacy",
    "net-benchmark dns list-resolvers --category family",
    "net-benchmark dns list-resolvers --format csv",
    "net-benchmark dns list-resolvers --format json",
    "net-benchmark dns list-domains",
    "net-benchmark dns list-domains --category tech",
    "net-benchmark dns list-domains --category ecommerce",
    "net-benchmark dns list-domains --category social",
    "net-benchmark dns list-domains --count 10",
    "net-benchmark dns list-domains --category news --count 5",
    "net-benchmark dns list-domains --format csv",
    "net-benchmark dns list-domains --format json",
    "net-benchmark dns list-categories",
    # Configuration management (commented out for speed)
    # "net-benchmark dns generate-config --output {{outdir}}/sample_config.yaml",
    # "net-benchmark dns generate-config --category security --output {{outdir}}/security_test.yaml",
    # "net-benchmark dns generate-config --category family --output {{outdir}}/family_protection.yaml",
    # "net-benchmark dns generate-config --category performance --output {{outdir}}/performance_test.yaml",
    # "net-benchmark dns generate-config --category privacy --output {{outdir}}/privacy_audit.yaml",
    # Performance optimization (commented out for speed)
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --max-concurrent 50 --timeout 3 --quiet --formats csv --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --timeout 10 --retries 3 --max-concurrent 10 --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --quiet --timeout 2 --output {{outdir}}",
    # Troubleshooting (keep help, comment out heavy)
    "python -m net_benchmark.dns_benchmark.cli --help",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv,excel --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --timeout 10 --retries 3 --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --max-concurrent 25 --output {{outdir}}",
    # f"python -m dns_benchmark.cli benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --output {{outdir}}",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --output {{outdir}}",
    # Use case examples (commented out for speed)
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats excel,pdf --output {{outdir}}/migration_analysis",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv,excel --output {{outdir}}/provider_selection",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --timeout 10 --retries 3 --formats csv --output {{outdir}}/troubleshooting",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats pdf --output {{outdir}}/security_assessment",
    # f"net-benchmark dns benchmark --resolvers {RESOLVERS} --domains {DOMAINS} --formats csv --quiet --output {{outdir}}/performance_monitoring",
]

# Give each test a readable ID instead of [0], [1], …
IDS = [f"cmd_{i}" for i in range(len(COMMANDS))]


@pytest.fixture(scope="session")
def temp_output_dir():
    """Create a temporary directory for all test outputs and clean up after all tests."""
    outdir = Path(tempfile.mkdtemp(prefix="dns_benchmark_test_"))
    print(f"\n=== Created test output directory: {outdir} ===\n")
    yield outdir


@pytest.mark.cli
@pytest.mark.parametrize("cmd", COMMANDS, ids=IDS)
def test_cli_command(cmd, temp_output_dir):
    """Run each CLI command and assert it completes successfully."""
    # Replace placeholder with actual temp directory
    cmd = cmd.replace("{{outdir}}", str(temp_output_dir))

    result = subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    # Preview output for debugging
    print("\n--- OUTPUT ---\n", result.stdout[:200])
    print("\n--- ERROR ---\n", result.stderr[:200])

    # Assert command exited cleanly
    assert result.returncode == 0, f"Command failed: {cmd}\n{result.stderr}"

    # Wait before next command to avoid blocking
    time.sleep(WAIT_INTERVAL)

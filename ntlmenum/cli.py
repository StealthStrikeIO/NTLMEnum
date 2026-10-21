"""Command-line interface for NTLMEnum."""

import argparse
import asyncio
import ipaddress
import logging
import sys

from ntlmenum import __version__
from ntlmenum.scanner import NTLMScanner, ScanConfig
from ntlmenum.output import write_output, FORMATTERS

logger = logging.getLogger("ntlmenum")

BANNER = r"""
    _   _ _____ _     __  __ _____
   | \ | |_   _| |   |  \/  | ____|_ __  _   _ _ __ ___
   |  \| | | | | |   | |\/| |  _| | '_ \| | | | '_ ` _ \
   | |\  | | | | |___| |  | | |___| | | | |_| | | | | | |
   |_| \_| |_| |_____|_|  |_|_____|_| |_|\__,_|_| |_| |_|
                                                  v{version}
   NTLM Authentication Endpoint Enumerator
"""


def parse_targets(args) -> list[str]:
    """Parse targets from arguments and input files."""
    targets = []

    if args.target:
        for t in args.target:
            targets.extend(expand_target(t))

    if args.targets_file:
        try:
            with open(args.targets_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.extend(expand_target(line))
        except FileNotFoundError:
            logger.error("Target file not found: %s", args.targets_file)
            sys.exit(1)

    return targets


def expand_target(target: str) -> list[str]:
    """Expand CIDR ranges and validate targets."""
    target = target.strip()
    if not target:
        return []

    # CIDR notation
    if "/" in target and not target.startswith("http"):
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > 65536:
                logger.warning(
                    "Large CIDR range %s (%d hosts) — consider narrowing scope",
                    target,
                    network.num_addresses,
                )
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            pass

    # IP range (e.g., 10.0.0.1-10)
    if "-" in target and not target.startswith("http"):
        parts = target.rsplit("-", 1)
        try:
            base_ip = ipaddress.ip_address(parts[0])
            end_octet = int(parts[1])
            if isinstance(base_ip, ipaddress.IPv4Address):
                octets = str(base_ip).rsplit(".", 1)
                start = int(octets[1])
                return [
                    f"{octets[0]}.{i}" for i in range(start, end_octet + 1)
                ]
        except (ValueError, IndexError):
            pass

    return [target]


def build_config(args) -> ScanConfig:
    """Build ScanConfig from parsed arguments."""
    schemes = []
    if args.scheme == "both":
        schemes = ["https", "http"]
    else:
        schemes = [args.scheme]

    methods = [m.upper() for m in args.methods]

    custom_paths = None
    if args.wordlist:
        custom_paths = []
        try:
            with open(args.wordlist) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        custom_paths.append((line, "Custom"))
        except FileNotFoundError:
            logger.error("Wordlist file not found: %s", args.wordlist)
            sys.exit(1)

    extra_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                key, val = h.split(":", 1)
                extra_headers[key.strip()] = val.strip()

    return ScanConfig(
        timeout=args.timeout,
        max_concurrent=args.threads,
        schemes=schemes,
        methods=methods,
        ports=args.ports or [],
        verify_ssl=args.verify_ssl,
        user_agent=args.user_agent,
        paths=custom_paths,
        custom_paths_only=args.custom_paths_only,
        proxy=args.proxy,
        headers=extra_headers,
        crawl=args.crawl,
        crawl_depth=args.crawl_depth,
        crawl_max_pages=args.crawl_max_pages,
    )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ntlmenum",
        description="Enumerate NTLM authentication endpoints and extract domain information",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  ntlmenum -t mail.example.com
  ntlmenum -t mail.example.com --crawl
  ntlmenum -t 10.0.0.0/24 --ports 80 443 8080
  ntlmenum -T targets.txt -o results.json -f json
  ntlmenum -t exchange.corp.local --methods GET POST OPTIONS -v
  ntlmenum -t 10.0.0.5 --crawl --crawl-depth 5 --crawl-max-pages 500
""",
    )

    # Targets
    target_group = parser.add_argument_group("targets")
    target_group.add_argument(
        "-t",
        "--target",
        action="append",
        help="Target host, IP, CIDR range, or URL (can specify multiple)",
    )
    target_group.add_argument(
        "-T",
        "--targets-file",
        help="File containing targets (one per line)",
    )

    # Scanning
    scan_group = parser.add_argument_group("scanning")
    scan_group.add_argument(
        "--scheme",
        choices=["http", "https", "both"],
        default="both",
        help="URL scheme to use (default: both)",
    )
    scan_group.add_argument(
        "--ports",
        type=int,
        nargs="+",
        help="Ports to scan (default: 80 for http, 443 for https)",
    )
    scan_group.add_argument(
        "--methods",
        nargs="+",
        default=["GET"],
        help="HTTP methods to try (default: GET)",
    )
    scan_group.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Maximum concurrent requests (default: 20)",
    )
    scan_group.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10)",
    )
    scan_group.add_argument(
        "--verify-ssl",
        action="store_true",
        default=False,
        help="Verify SSL certificates (default: disabled)",
    )
    scan_group.add_argument(
        "--proxy",
        help="HTTP proxy URL (e.g., http://127.0.0.1:8080)",
    )
    scan_group.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        help="Custom User-Agent string",
    )
    scan_group.add_argument(
        "-H",
        "--header",
        action="append",
        help="Custom header (format: 'Name: Value')",
    )

    # Wordlist
    path_group = parser.add_argument_group("paths")
    path_group.add_argument(
        "-w",
        "--wordlist",
        help="Custom path wordlist file (one path per line)",
    )
    path_group.add_argument(
        "--custom-paths-only",
        action="store_true",
        help="Only use custom wordlist, skip built-in paths",
    )

    # Crawling
    crawl_group = parser.add_argument_group("crawling")
    crawl_group.add_argument(
        "--crawl",
        action="store_true",
        help="Crawl each target to discover additional endpoints beyond the wordlist",
    )
    crawl_group.add_argument(
        "--crawl-depth",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)",
    )
    crawl_group.add_argument(
        "--crawl-max-pages",
        type=int,
        default=200,
        help="Maximum pages to crawl per target (default: 200)",
    )

    # Output
    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "-o",
        "--output",
        help="Output file path",
    )
    output_group.add_argument(
        "-f",
        "--format",
        choices=list(FORMATTERS.keys()),
        default="table",
        help="Output format (default: table)",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output (show negotiate flags, extra details)",
    )
    output_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress banner and progress output",
    )
    output_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    # Logging setup
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    elif args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    if not args.quiet:
        sys.stderr.write(BANNER.format(version=__version__))
        sys.stderr.write("\n")

    targets = parse_targets(args)
    if not targets:
        parser.error("No targets specified. Use -t or -T to provide targets.")

    if not args.quiet:
        sys.stderr.write(f"  Targets: {len(targets)} host(s)\n")
        sys.stderr.write(f"  Schemes: {args.scheme}\n")
        sys.stderr.write(f"  Methods: {', '.join(m.upper() for m in args.methods)}\n")
        sys.stderr.write(f"  Threads: {args.threads}\n")
        if args.crawl:
            sys.stderr.write(f"  Crawl:   enabled (depth={args.crawl_depth}, max_pages={args.crawl_max_pages})\n")
        sys.stderr.write("\n")

    config = build_config(args)
    scanner = NTLMScanner(config)

    def progress(completed, total):
        if not args.quiet:
            sys.stderr.write(f"\r  Probing: {completed}/{total} endpoints")
            sys.stderr.flush()

    def crawl_progress(pages_crawled, urls_found):
        if not args.quiet:
            sys.stderr.write(f"\r  Crawling: {pages_crawled} pages visited, {urls_found} URLs discovered")
            sys.stderr.flush()

    try:
        results = asyncio.run(scanner.scan_targets(
            targets,
            progress_callback=progress,
            crawl_callback=crawl_progress if args.crawl else None,
        ))
    except KeyboardInterrupt:
        sys.stderr.write("\n\n  Scan interrupted.\n")
        sys.exit(130)

    if not args.quiet:
        sys.stderr.write("\n")

    write_output(results, fmt=args.format, output_file=args.output, verbose=args.verbose)

    if args.output and not args.quiet:
        sys.stderr.write(f"\n  Results written to: {args.output}\n")

"""Output formatting for scan results."""

import csv
import io
import json
import sys
from datetime import datetime, timezone

from ntlmenum.scanner import ScanResult


def format_table(results: list[ScanResult], verbose: bool = False) -> str:
    """Format results as a readable table."""
    if not results:
        return "No NTLM endpoints found."

    lines = []

    # Group by unique domain/host combos for a summary
    seen_hosts: dict[str, ScanResult] = {}
    for r in results:
        key = f"{r.challenge.netbios_domain_name}\\{r.challenge.netbios_computer_name}"
        if key not in seen_hosts:
            seen_hosts[key] = r

    lines.append("")
    lines.append("=" * 80)
    lines.append("  NTLM ENUMERATION RESULTS")
    lines.append("=" * 80)

    # Host summary
    for key, r in seen_hosts.items():
        c = r.challenge
        lines.append("")
        lines.append(f"  Target: {key}")
        lines.append(f"  {'─' * 70}")
        if c.dns_computer_name:
            lines.append(f"  FQDN:           {c.dns_computer_name}")
        if c.dns_domain_name:
            lines.append(f"  DNS Domain:     {c.dns_domain_name}")
        if c.dns_tree_name:
            lines.append(f"  DNS Forest:     {c.dns_tree_name}")
        if c.netbios_domain_name:
            lines.append(f"  NetBIOS Domain: {c.netbios_domain_name}")
        if c.netbios_computer_name:
            lines.append(f"  NetBIOS Name:   {c.netbios_computer_name}")
        if c.version:
            lines.append(
                f"  OS Version:     {c.version} ({c.version.product_name})"
            )
        if c.timestamp:
            lines.append(f"  Server Time:    {c.timestamp.isoformat()}")
            skew = c.timestamp - datetime.now(timezone.utc)
            skew_seconds = int(skew.total_seconds())
            if abs(skew_seconds) > 5:
                lines.append(f"  Clock Skew:     {skew_seconds:+d} seconds")
        if c.supports_ntlmv1():
            lines.append("  ⚠ NTLMv1 Supported (weak authentication)")

        if verbose:
            lines.append(f"  Flags:          {', '.join(c.flag_names())}")

    # Endpoint listing
    lines.append("")
    lines.append("  DISCOVERED ENDPOINTS")
    lines.append(f"  {'─' * 70}")

    # Calculate column widths
    url_width = max(len(r.url) for r in results)
    url_width = min(url_width, 60)
    cat_width = max(len(r.category) for r in results)

    header = f"  {'URL':<{url_width}}  {'Method':<7}  {'Category':<{cat_width}}  {'Auth Header'}"
    lines.append(header)
    lines.append(f"  {'─' * len(header)}")

    for r in results:
        url_display = r.url if len(r.url) <= url_width else r.url[: url_width - 3] + "..."
        lines.append(
            f"  {url_display:<{url_width}}  {r.method:<7}  {r.category:<{cat_width}}  {r.auth_header}"
        )

    lines.append("")
    lines.append(f"  Total: {len(results)} endpoint(s) found")
    lines.append("=" * 80)
    lines.append("")

    return "\n".join(lines)


def format_json(results: list[ScanResult], indent: int = 2) -> str:
    """Format results as JSON."""
    data = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_endpoints": len(results),
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(data, indent=indent, default=str)


def format_csv(results: list[ScanResult]) -> str:
    """Format results as CSV."""
    output = io.StringIO()
    if not results:
        return ""

    fieldnames = [
        "url",
        "path",
        "category",
        "method",
        "auth_header",
        "auth_scheme",
        "status_code",
        "netbios_domain_name",
        "netbios_computer_name",
        "dns_domain_name",
        "dns_computer_name",
        "dns_tree_name",
        "os_version",
        "os_product",
        "timestamp",
        "supports_ntlmv1",
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for r in results:
        row = {
            "url": r.url,
            "path": r.path,
            "category": r.category,
            "method": r.method,
            "auth_header": r.auth_header,
            "auth_scheme": r.auth_scheme,
            "status_code": r.status_code,
            "netbios_domain_name": r.challenge.netbios_domain_name,
            "netbios_computer_name": r.challenge.netbios_computer_name,
            "dns_domain_name": r.challenge.dns_domain_name,
            "dns_computer_name": r.challenge.dns_computer_name,
            "dns_tree_name": r.challenge.dns_tree_name,
            "os_version": str(r.challenge.version) if r.challenge.version else "",
            "os_product": r.challenge.version.product_name if r.challenge.version else "",
            "timestamp": r.challenge.timestamp.isoformat() if r.challenge.timestamp else "",
            "supports_ntlmv1": r.challenge.supports_ntlmv1(),
        }
        writer.writerow(row)

    return output.getvalue()


def format_jsonl(results: list[ScanResult]) -> str:
    """Format results as JSONL (one JSON object per line)."""
    lines = []
    for r in results:
        lines.append(json.dumps(r.to_dict(), default=str))
    return "\n".join(lines)


FORMATTERS = {
    "table": format_table,
    "json": format_json,
    "csv": format_csv,
    "jsonl": format_jsonl,
}


def write_output(
    results: list[ScanResult],
    fmt: str = "table",
    output_file: str | None = None,
    verbose: bool = False,
) -> None:
    """Write formatted results to file or stdout."""
    formatter = FORMATTERS.get(fmt)
    if not formatter:
        raise ValueError(f"Unknown format: {fmt}. Use: {', '.join(FORMATTERS)}")

    if fmt == "table":
        text = formatter(results, verbose=verbose)
    else:
        text = formatter(results)

    if output_file:
        with open(output_file, "w") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")

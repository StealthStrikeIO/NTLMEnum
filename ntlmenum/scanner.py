"""
Async NTLM endpoint scanner.

Probes HTTP(S) endpoints for NTLM authentication and extracts
domain/host information from Type 2 challenge responses.
"""

import asyncio
import ssl
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ntlmenum.ntlm import (
    build_ntlm_negotiate_b64,
    extract_ntlm_challenge,
    NTLMChallenge,
)
from ntlmenum.paths import NTLM_PATHS
from ntlmenum.crawler import Crawler, CrawlConfig

logger = logging.getLogger("ntlmenum")

AUTH_HEADERS = ("www-authenticate", "proxy-authenticate")
PROBE_METHODS = ("GET", "POST", "OPTIONS")


@dataclass
class ScanResult:
    """Result from probing a single URL endpoint."""
    url: str
    path: str
    category: str
    method: str
    auth_header: str
    auth_scheme: str
    challenge: NTLMChallenge
    status_code: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "path": self.path,
            "category": self.category,
            "method": self.method,
            "auth_header": self.auth_header,
            "auth_scheme": self.auth_scheme,
            "status_code": self.status_code,
            "timestamp": self.timestamp.isoformat(),
            **self.challenge.to_dict(),
        }


@dataclass
class ScanConfig:
    """Scanner configuration."""
    timeout: float = 10.0
    max_concurrent: int = 20
    schemes: list[str] = field(default_factory=lambda: ["https", "http"])
    methods: list[str] = field(default_factory=lambda: ["GET"])
    ports: list[int] = field(default_factory=list)
    verify_ssl: bool = False
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    paths: list[tuple[str, str]] | None = None
    custom_paths_only: bool = False
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    crawl: bool = False
    crawl_depth: int = 3
    crawl_max_pages: int = 200


class NTLMScanner:
    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self._negotiate_b64 = build_ntlm_negotiate_b64()
        self._semaphore: asyncio.Semaphore | None = None
        self._results: list[ScanResult] = []
        self._failed_origins: set[str] = set()
        self._lock = asyncio.Lock()

    def _get_paths(self) -> list[tuple[str, str]]:
        custom = self.config.paths or []
        if self.config.custom_paths_only:
            return custom
        return NTLM_PATHS + custom

    def _build_urls(self, target: str) -> list[tuple[str, str, str]]:
        """
        Build (url, path, category) tuples for a target.
        Target can be: hostname, hostname:port, or full URL.
        """
        urls = []
        parsed = urlparse(target)

        if parsed.scheme in ("http", "https"):
            # Full URL provided — scan just that URL with its path
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path or "/"
            urls.append((base + path, path, "UserProvided"))
            # Also scan all paths against this base
            for p, cat in self._get_paths():
                urls.append((base + p, p, cat))
            return urls

        # Bare host or host:port
        host = target
        explicit_ports = list(self.config.ports)

        if ":" in host and not host.startswith("["):
            parts = host.rsplit(":", 1)
            if parts[1].isdigit():
                host = parts[0]
                explicit_ports = [int(parts[1])]

        for scheme in self.config.schemes:
            if explicit_ports:
                port_list = explicit_ports
            else:
                port_list = [443 if scheme == "https" else 80]

            for port in port_list:
                default_port = (scheme == "https" and port == 443) or (
                    scheme == "http" and port == 80
                )
                if default_port:
                    base = f"{scheme}://{host}"
                else:
                    base = f"{scheme}://{host}:{port}"

                for path, cat in self._get_paths():
                    urls.append((base + path, path, cat))

        return urls

    async def _check_ntlm_auth(
        self,
        client: httpx.AsyncClient,
        url: str,
        path: str,
        category: str,
    ) -> list[ScanResult]:
        """Probe a URL for NTLM authentication using configured methods."""
        results = []
        origin = urlparse(url).netloc

        async with self._semaphore:
            # Skip if we've already seen this origin fail on connectivity
            async with self._lock:
                if origin in self._failed_origins:
                    return []

            for method in self.config.methods:
                try:
                    # Step 1: Initial request to see if NTLM auth is offered
                    resp = await client.request(method, url)

                    ntlm_headers = self._find_ntlm_headers(resp)
                    if not ntlm_headers:
                        continue

                    # Step 2: Send NTLM Type 1 negotiate for each auth header
                    for header_name, scheme in ntlm_headers:
                        # Match the scheme the server advertised
                        auth_scheme = scheme if scheme in ("NTLM", "Negotiate") else "NTLM"
                        negotiate_value = f"{auth_scheme} {self._negotiate_b64}"
                        auth_resp = await client.request(
                            method,
                            url,
                            headers={
                                "Authorization": negotiate_value,
                            },
                        )

                        # Parse Type 2 challenge from response
                        challenge = self._extract_challenge(auth_resp, header_name)
                        if challenge:
                            result = ScanResult(
                                url=url,
                                path=path,
                                category=category,
                                method=method,
                                auth_header=header_name,
                                auth_scheme=scheme,
                                challenge=challenge,
                                status_code=auth_resp.status_code,
                            )
                            results.append(result)
                            logger.info(
                                "NTLM endpoint found: %s [%s] -> %s\\%s",
                                url,
                                method,
                                challenge.netbios_domain_name,
                                challenge.netbios_computer_name,
                            )
                            # Got a valid challenge on this method, no need to try others
                            break

                    if results:
                        break

                except httpx.ConnectError:
                    async with self._lock:
                        self._failed_origins.add(origin)
                    logger.debug("Connection failed: %s", url)
                    return []
                except (httpx.TimeoutException, httpx.HTTPError) as e:
                    logger.debug("Request error for %s: %s", url, e)
                    continue
                except Exception as e:
                    logger.debug("Unexpected error for %s: %s", url, e)
                    continue

        return results

    def _find_ntlm_headers(
        self, response: httpx.Response
    ) -> list[tuple[str, str]]:
        """
        Find auth headers that advertise NTLM or Negotiate.
        Returns list of (header_name, scheme) tuples.
        """
        found = []
        for header_name in AUTH_HEADERS:
            values = response.headers.get_list(header_name)
            for value in values:
                val_lower = value.lower().strip()
                if val_lower.startswith("ntlm"):
                    found.append((header_name, "NTLM"))
                elif val_lower.startswith("negotiate"):
                    found.append((header_name, "Negotiate"))
        return found

    def _extract_challenge(
        self, response: httpx.Response, header_name: str
    ) -> NTLMChallenge | None:
        """Extract NTLM challenge from response auth headers."""
        values = response.headers.get_list(header_name)
        for value in values:
            challenge = extract_ntlm_challenge(value)
            if challenge is not None:
                return challenge
        return None

    async def _crawl_target(
        self,
        target: str,
        crawl_callback=None,
    ) -> list[tuple[str, str, str]]:
        """Crawl a target to discover additional URLs."""
        crawl_config = CrawlConfig(
            max_depth=self.config.crawl_depth,
            max_pages=self.config.crawl_max_pages,
            timeout=self.config.timeout,
            max_concurrent=self.config.max_concurrent,
            user_agent=self.config.user_agent,
            verify_ssl=self.config.verify_ssl,
            proxy=self.config.proxy,
            headers=self.config.headers,
        )
        crawler = Crawler(crawl_config)

        # Determine start URLs from the target
        parsed = urlparse(target)
        if parsed.scheme in ("http", "https"):
            start_urls = [target]
        else:
            host = target
            if ":" in host and not host.startswith("["):
                parts = host.rsplit(":", 1)
                if parts[1].isdigit():
                    host = parts[0]
            start_urls = []
            for scheme in self.config.schemes:
                ports = self.config.ports or [443 if scheme == "https" else 80]
                for port in ports:
                    default_port = (scheme == "https" and port == 443) or (
                        scheme == "http" and port == 80
                    )
                    if default_port:
                        start_urls.append(f"{scheme}://{host}")
                    else:
                        start_urls.append(f"{scheme}://{host}:{port}")

        crawled_urls = []
        for start_url in start_urls:
            logger.info("Crawling %s (depth=%d, max_pages=%d)",
                        start_url, crawl_config.max_depth, crawl_config.max_pages)
            result = await crawler.crawl(start_url, progress_callback=crawl_callback)
            for url in result.discovered_urls:
                path = urlparse(url).path or "/"
                crawled_urls.append((url, path, "Crawled"))

        return crawled_urls

    async def scan_target(
        self,
        target: str,
        progress_callback=None,
        crawl_callback=None,
    ) -> list[ScanResult]:
        """Scan a single target for NTLM endpoints."""
        urls = self._build_urls(target)

        # Crawl for additional URLs if enabled
        if self.config.crawl:
            crawled = await self._crawl_target(target, crawl_callback)
            # Merge crawled URLs, deduplicating against wordlist URLs
            existing = {u.lower() for u, _, _ in urls}
            for url, path, cat in crawled:
                if url.lower() not in existing:
                    existing.add(url.lower())
                    urls.append((url, path, cat))
                # Also try the opposite trailing-slash variant
                if url.endswith("/"):
                    alt = url.rstrip("/")
                    alt_path = path.rstrip("/") or "/"
                else:
                    alt = url + "/"
                    alt_path = path + "/"
                if alt.lower() not in existing:
                    existing.add(alt.lower())
                    urls.append((alt, alt_path, cat))

        if not urls:
            return []

        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)

        transport_kwargs = {}
        if not self.config.verify_ssl:
            transport_kwargs["verify"] = False

        client_kwargs = {
            "timeout": httpx.Timeout(self.config.timeout),
            "follow_redirects": False,
            "headers": {
                "User-Agent": self.config.user_agent,
                **self.config.headers,
            },
            **transport_kwargs,
        }
        if self.config.proxy:
            client_kwargs["proxy"] = self.config.proxy

        results = []
        seen_endpoints: set[str] = set()

        async with httpx.AsyncClient(**client_kwargs) as client:
            tasks = []
            for url, path, category in urls:
                tasks.append(self._check_ntlm_auth(client, url, path, category))

            completed = 0
            total = len(tasks)

            for coro in asyncio.as_completed(tasks):
                try:
                    scan_results = await coro
                    for r in scan_results:
                        key = (
                            r.url,
                            r.challenge.netbios_domain_name,
                            r.challenge.netbios_computer_name,
                        )
                        if key not in seen_endpoints:
                            seen_endpoints.add(key)
                            results.append(r)
                except Exception as e:
                    logger.debug("Task error: %s", e)

                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        return results

    async def scan_targets(
        self,
        targets: list[str],
        progress_callback=None,
        crawl_callback=None,
    ) -> list[ScanResult]:
        """Scan multiple targets."""
        all_results = []
        for i, target in enumerate(targets):
            logger.info("Scanning target %d/%d: %s", i + 1, len(targets), target)
            results = await self.scan_target(target, progress_callback, crawl_callback)
            all_results.extend(results)
        return all_results

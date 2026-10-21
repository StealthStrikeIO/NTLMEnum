"""
Async web crawler for endpoint discovery.

Spiders a target site to find URLs that may have NTLM authentication,
rather than relying solely on a static wordlist.
"""

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse, urlunparse
from dataclasses import dataclass, field
from html.parser import HTMLParser

import httpx

logger = logging.getLogger("ntlmenum")

LINK_ATTRS = {
    "a": "href",
    "form": "action",
    "script": "src",
    "link": "href",
    "img": "src",
    "iframe": "src",
    "area": "href",
    "frame": "src",
    "embed": "src",
    "object": "data",
}

SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
    ".exe", ".dll", ".msi", ".bin",
})


class LinkExtractor(HTMLParser):
    """Extract URLs from HTML content."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_name = LINK_ATTRS.get(tag.lower())
        if not attr_name:
            return
        for name, value in attrs:
            if name.lower() == attr_name and value:
                self.links.append(value)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]):
        self.handle_starttag(tag, attrs)


def extract_links(html: str, base_url: str) -> set[str]:
    """Extract and resolve all links from HTML content."""
    parser = LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass

    # Also grab URLs from inline JS/CSS patterns like fetch('/api/...')
    js_urls = re.findall(r'''(?:fetch|url|href|src|action)\s*[\(=]\s*['\"]([^'\"]+)['\"]''', html)
    parser.links.extend(js_urls)

    urls = set()
    for link in parser.links:
        link = link.strip()
        if not link or link.startswith(("#", "javascript:", "mailto:", "data:", "tel:")):
            continue
        try:
            resolved = urljoin(base_url, link)
            urls.add(resolved)
        except Exception:
            continue

    return urls


def normalize_url(url: str) -> str:
    """Normalize a URL for deduplication, preserving trailing slashes."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path,
        parsed.params,
        parsed.query,
        "",
    ))


def is_same_origin(url: str, base_url: str) -> bool:
    """Check if a URL belongs to the same origin as the base."""
    parsed = urlparse(url)
    base_parsed = urlparse(base_url)
    return (
        parsed.scheme.lower() == base_parsed.scheme.lower()
        and parsed.netloc.lower() == base_parsed.netloc.lower()
    )


def should_skip(url: str) -> bool:
    """Check if a URL should be skipped based on extension."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


@dataclass
class CrawlConfig:
    """Crawler configuration."""
    max_depth: int = 3
    max_pages: int = 200
    timeout: float = 10.0
    max_concurrent: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    verify_ssl: bool = False
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlResult:
    """Result of crawling a target."""
    discovered_urls: list[str]
    pages_crawled: int
    errors: int


class Crawler:
    """Async web crawler for endpoint discovery."""

    def __init__(self, config: CrawlConfig | None = None):
        self.config = config or CrawlConfig()
        self._visited: set[str] = set()
        self._discovered: set[str] = set()
        self._semaphore: asyncio.Semaphore | None = None
        self._pages_crawled = 0
        self._errors = 0
        self._lock = asyncio.Lock()

    async def crawl(
        self,
        start_url: str,
        progress_callback=None,
    ) -> CrawlResult:
        """
        Crawl a target starting from start_url.
        Returns all discovered same-origin URLs.
        """
        self._visited = set()
        self._discovered = set()
        self._pages_crawled = 0
        self._errors = 0
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)

        # Normalize the start URL
        parsed = urlparse(start_url)
        if not parsed.scheme:
            start_url = f"https://{start_url}"
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        client_kwargs = {
            "timeout": httpx.Timeout(self.config.timeout),
            "follow_redirects": True,
            "max_redirects": 5,
            "headers": {
                "User-Agent": self.config.user_agent,
                **self.config.headers,
            },
            "verify": self.config.verify_ssl,
        }
        if self.config.proxy:
            client_kwargs["proxy"] = self.config.proxy

        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((start_url, 0))
        self._discovered.add(normalize_url(start_url))

        async with httpx.AsyncClient(**client_kwargs) as client:
            workers = [
                asyncio.create_task(
                    self._worker(client, queue, base_url, progress_callback)
                )
                for _ in range(self.config.max_concurrent)
            ]

            # Wait for queue to drain
            await queue.join()

            # Cancel workers
            for w in workers:
                w.cancel()

        discovered_list = sorted(self._discovered)
        logger.info("Crawl complete: %d URLs discovered from %d pages",
                     len(discovered_list), self._pages_crawled)

        return CrawlResult(
            discovered_urls=discovered_list,
            pages_crawled=self._pages_crawled,
            errors=self._errors,
        )

    async def _worker(
        self,
        client: httpx.AsyncClient,
        queue: asyncio.Queue[tuple[str, int]],
        base_url: str,
        progress_callback,
    ):
        while True:
            try:
                url, depth = await asyncio.wait_for(queue.get(), timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                return

            try:
                await self._process_url(client, queue, url, depth, base_url, progress_callback)
            except asyncio.CancelledError:
                queue.task_done()
                return
            except Exception as e:
                logger.debug("Worker error on %s: %s", url, e)
                async with self._lock:
                    self._errors += 1
            finally:
                queue.task_done()

    async def _process_url(
        self,
        client: httpx.AsyncClient,
        queue: asyncio.Queue[tuple[str, int]],
        url: str,
        depth: int,
        base_url: str,
        progress_callback,
    ):
        normalized = normalize_url(url)

        async with self._lock:
            if normalized in self._visited:
                return
            if self._pages_crawled >= self.config.max_pages:
                return
            self._visited.add(normalized)

        async with self._semaphore:
            try:
                resp = await client.get(url)
            except (httpx.HTTPError, Exception) as e:
                logger.debug("Crawl error %s: %s", url, e)
                async with self._lock:
                    self._errors += 1
                return

        async with self._lock:
            self._pages_crawled += 1

        if progress_callback:
            progress_callback(self._pages_crawled, len(self._discovered))

        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return

        if depth >= self.config.max_depth:
            return

        # Extract links from HTML
        try:
            links = extract_links(resp.text, str(resp.url))
        except Exception:
            return

        for link in links:
            if not is_same_origin(link, base_url):
                continue
            if should_skip(link):
                continue

            link_normalized = normalize_url(link)

            async with self._lock:
                if link_normalized in self._discovered:
                    continue
                self._discovered.add(link_normalized)

                if link_normalized not in self._visited and self._pages_crawled < self.config.max_pages:
                    await queue.put((link, depth + 1))

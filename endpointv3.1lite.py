#!/usr/bin/env python3
"""
Advanced API Endpoint Discovery Tool v2.0
Enhanced with comprehensive analysis and beautiful reporting
"""

import asyncio
import aiohttp
import argparse
import json
import logging
import random
import re
import time
import urllib.parse
from pathlib import Path
from typing import Set, Dict, List, Optional
import ssl
from urllib.parse import urljoin, urlparse, parse_qs

# Color codes for terminal output
COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'purple': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m',
    'bold': '\033[1m',
    'reset': '\033[0m'
}

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
]

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('api_discovery')

# Default wordlist for endpoint discovery
DEFAULT_WORDLIST = [
    # Common API endpoints
    "api", "v1", "v2", "v3", "rest", "graphql", "webhook", "callback",
    
    # Authentication & Authorization
    "auth", "login", "logout", "register", "signup", "signin", "oauth", "token",
    "refresh", "verify", "reset", "forgot", "password", "session", "sso",
    
    # User management
    "user", "users", "profile", "account", "accounts", "member", "members",
    "admin", "administrator", "root", "superuser", "staff",
    
    # Data operations
    "data", "info", "list", "search", "query", "filter", "sort", "export",
    "import", "upload", "download", "file", "files", "media", "assets",
    
    # CRUD operations
    "create", "read", "update", "delete", "get", "post", "put", "patch",
    "remove", "add", "edit", "modify", "save", "insert",
    
    # Configuration & Settings
    "config", "settings", "options", "preferences", "env", "environment",
    "status", "health", "ping", "version", "info", "about",
    
    # Database & Storage
    "db", "database", "sql", "mongo", "redis", "cache", "storage", "backup",
    "restore", "migrate", "seed", "dump", "export", "import",
    
    # Monitoring & Logging
    "logs", "log", "monitor", "metrics", "stats", "analytics", "reports",
    "debug", "trace", "error", "errors", "exceptions",
    
    # Development & Testing
    "test", "tests", "dev", "development", "staging", "prod", "production",
    "demo", "sample", "example", "mock", "stub", "fixture",
    
    # Documentation
    "docs", "doc", "documentation", "help", "guide", "tutorial", "readme",
    "api-docs", "swagger", "openapi", "schema", "spec",
    
    # Security
    "security", "secure", "ssl", "tls", "cert", "certificate", "key", "keys",
    "encrypt", "decrypt", "hash", "signature", "validate", "verify",
    
    # Notifications & Messaging
    "notify", "notification", "notifications", "message", "messages", "mail",
    "email", "sms", "push", "alert", "alerts", "broadcast",
    
    # Payment & Commerce
    "payment", "pay", "billing", "invoice", "order", "orders", "cart",
    "checkout", "transaction", "transactions", "refund", "subscription",
    
    # Content Management
    "content", "cms", "page", "pages", "post", "posts", "article", "articles",
    "blog", "news", "category", "categories", "tag", "tags",
    
    # File System
    "public", "private", "static", "assets", "resources", "images", "img",
    "css", "js", "fonts", "videos", "audio", "documents", "pdf",
    
    # Framework specific
    "wp-json", "wp-admin", "wp-content", "wp-includes", "wordpress",
    "drupal", "joomla", "laravel", "symfony", "rails", "django",
    "express", "flask", "spring", "struts", "zend",
    
    # Server & Infrastructure
    "server", "proxy", "load-balancer", "cdn", "aws", "azure", "gcp",
    "docker", "kubernetes", "k8s", "helm", "terraform",
    
    # Common directories
    "bin", "etc", "var", "tmp", "temp", "cache", "logs", "lib", "src",
    "dist", "build", "node_modules", "vendor", "packages",
    
    # API versioning
    "api/v1", "api/v2", "api/v3", "v1/api", "v2/api", "v3/api",
    "rest/v1", "rest/v2", "graphql/v1",
    
    # Mobile & Apps
    "mobile", "app", "apps", "ios", "android", "cordova", "phonegap",
    "react-native", "flutter", "xamarin",
    
    # Social & Integration
    "social", "facebook", "twitter", "google", "github", "linkedin",
    "instagram", "youtube", "tiktok", "discord", "slack", "teams",
    
    # Analytics & Tracking
    "analytics", "tracking", "pixel", "beacon", "gtm", "ga", "mixpanel",
    "amplitude", "segment", "hotjar", "fullstory",
    
    # Common file extensions as endpoints
    "sitemap.xml", "robots.txt", "humans.txt", "security.txt", "ads.txt",
    "manifest.json", "package.json", "composer.json", "requirements.txt",
    
    # Hidden/Sensitive
    ".env", ".git", ".svn", ".htaccess", ".htpasswd", "web.config",
    "config.php", "config.json", "settings.json", "local.json",
    
    # Backup files
    "backup", "backups", "bak", "old", "orig", "copy", "archive",
    "dump.sql", "database.sql", "backup.zip", "site.zip"
]

# Common parameters for testing
COMMON_PARAMETERS = [
    # Authentication parameters
    "username", "password", "email", "token", "access_token", "refresh_token",
    "api_key", "client_id", "client_secret", "grant_type", "response_type",
    "redirect_uri", "scope", "state", "code",
    
    # Pagination parameters
    "page", "limit", "offset", "per_page", "size", "count", "start", "end",
    
    # Filtering parameters
    "filter", "search", "q", "query", "sort", "order", "order_by", "group_by",
    
    # Common identifiers
    "id", "user_id", "account_id", "session_id", "request_id", "trace_id",
    
    # Data format parameters
    "format", "type", "content_type", "accept", "encoding", "charset",
    
    # Callback parameters
    "callback", "jsonp", "success", "error", "complete",
    
    # Timestamp parameters
    "timestamp", "time", "date", "created", "updated", "modified",
    
    # File parameters
    "file", "filename", "path", "url", "link", "src", "href",
    
    # Debug parameters
    "debug", "verbose", "trace", "log_level", "dev", "test"
]

class ApiEndpointDiscovery:
    def __init__(self, base_url: str, concurrency: int = 10, timeout: int = 10, 
                 delay: float = 0.1, headers: Dict = None, cookies: Dict = None,
                 auth: tuple = None, proxy: str = None, wordlist_path: str = None,
                 output_file: str = None, verbose: bool = False, max_depth: int = 3):
        
        self.base_url = base_url.rstrip('/')
        self.concurrency = concurrency
        self.timeout = timeout
        self.delay = delay
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.auth = auth
        self.proxy = proxy
        self.output_file = output_file
        self.verbose = verbose
        self.max_depth = max_depth
        
        # Load wordlist
        self.wordlist = self._load_wordlist(wordlist_path)
        
        # Results storage
        self.discovered_endpoints: Set[str] = set()
        self.endpoint_methods: Dict[str, Set[str]] = {}
        self.endpoint_responses: Dict[str, Dict[str, int]] = {}
        self.discovered_parameters: Dict[str, Set[str]] = {}
        self.interesting_findings: List[Dict] = []
        
        # Statistics
        self.request_count = 0
        self.rate_limit_hits = 0
        self.start_time = 0
        
        # Session management
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        
        # Create results directory
        Path("results").mkdir(exist_ok=True)
        
        # Prepare endpoints for testing
        self.endpoints = self._prepare_endpoints()
        
        logger.info(f"Loaded {len(self.endpoints)} endpoints for testing")

    def _load_wordlist(self, wordlist_path: Optional[str]) -> List[str]:
        """Load wordlist from file or use default"""
        if wordlist_path and Path(wordlist_path).exists():
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    custom_wordlist = [line.strip() for line in f if line.strip()]
                logger.info(f"Loaded {len(custom_wordlist)} endpoints from {wordlist_path}")
                return custom_wordlist
            except Exception as e:
                logger.warning(f"Failed to load wordlist from {wordlist_path}: {e}")
        
        return DEFAULT_WORDLIST

    def _prepare_endpoints(self) -> List[str]:
        """Prepare list of endpoints to test"""
        endpoints = set()
        
        # Add wordlist endpoints
        for endpoint in self.wordlist:
            endpoints.add(endpoint.lstrip('/'))
        
        # Add common variations
        variations = []
        for endpoint in list(endpoints):
            if not any(char in endpoint for char in ['/', '.', '_']):
                variations.extend([
                    f"{endpoint}s",  # plural
                    f"{endpoint}_api",
                    f"api_{endpoint}",
                    f"{endpoint}/api",
                    f"api/{endpoint}",
                ])
        
        endpoints.update(variations)
        return list(endpoints)

    async def discover(self):
        """Main discovery method"""
        self.start_time = time.time()
        
        logger.info(f"{COLORS['bold']}{COLORS['blue']}Advanced API Endpoint Discovery Tool v2.0{COLORS['reset']}")
        logger.info(f"Target: {self.base_url}")
        logger.info(f"Concurrency: {self.concurrency}, Timeout: {self.timeout}s, Initial delay: {self.delay}s")
        
        # Setup session and semaphore
        connector = aiohttp.TCPConnector(
            limit=self.concurrency * 2,
            limit_per_host=self.concurrency,
            ssl=ssl.create_default_context()
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            cookies=self.cookies
        )
        self.semaphore = asyncio.Semaphore(self.concurrency)
        
        try:
            logger.info(f"{COLORS['cyan']}Starting comprehensive endpoint discovery...{COLORS['reset']}")
            
            # Phase 1: Information Disclosure Sources
            logger.info("Phase 1: Information Disclosure Sources")
            await self._check_information_disclosure()
            
            # Phase 2: Endpoint Discovery
            logger.info("Phase 2: Endpoint Discovery")
            await self._discover_endpoints()
            
            # Phase 3: HTTP Method Testing
            logger.info("Phase 3: HTTP Method Testing")
            await self._test_http_methods()
            
            # Phase 4: Parameter Discovery
            logger.info("Phase 4: Parameter Discovery")
            await self._discover_parameters()
            
            # Phase 6: Analysis and Reporting
            logger.info("Phase 5: Analysis")
            await self._analyze_findings()
            
        finally:
            await self.session.close()
        
        # Generate reports
        self._generate_reports()

    async def _check_information_disclosure(self):
        """Check for information disclosure sources"""
        disclosure_sources = [
            "robots.txt", "sitemap.xml", "sitemap_index.xml", "sitemap.txt",
            ".well-known/security.txt", ".well-known/humans.txt",
            "humans.txt", "ads.txt", "manifest.json", "package.json",
            "composer.json", "bower.json", "gulpfile.js", "webpack.config.js",
            ".env", ".env.example", ".env.local", ".env.production",
            "config.json", "settings.json", "app.json", "web.config",
            "crossdomain.xml", "clientaccesspolicy.xml"
        ]
        
        # Check robots.txt
        logger.info("Checking robots.txt for disclosed paths...")
        await self._check_robots_txt()
        
        # Check sitemap files
        logger.info("Checking sitemap files...")
        await self._check_sitemaps()
        
        # Analyze JavaScript files
        logger.info("Analyzing JavaScript files for endpoints...")
        await self._analyze_javascript_files()
        
        # Analyze HTML pages
        logger.info("Analyzing HTML pages for API endpoints...")
        await self._analyze_html_pages()
        
        # Check for SPA patterns
        logger.info("Checking for SPA API patterns...")
        await self._check_spa_patterns()
        
        # Check configuration files
        logger.info("Checking for configuration files...")
        await self._check_config_files()
        
        # Search for API documentation
        logger.info("Searching for API documentation...")
        await self._check_api_documentation()

    async def _check_robots_txt(self):
        """Check robots.txt for disclosed paths"""
        try:
            url = f"{self.base_url}/robots.txt"
            async with self.semaphore:
                async with self.session.get(url, headers=self._get_headers()) as response:
                    self.request_count += 1
                    if response.status == 200:
                        logger.info("Found robots.txt")
                        content = await response.text()
                        
                        # Extract disallowed paths
                        disallow_pattern = re.compile(r'Disallow:\s*(.+)', re.IGNORECASE)
                        paths = []
                        for match in disallow_pattern.finditer(content):
                            path = match.group(1).strip()
                            if path and path != '/':
                                paths.append(path.lstrip('/'))
                        
                        if paths:
                            logger.info(f"Extracted {len(paths)} paths from robots.txt")
                            self.endpoints.extend(paths)
                            self.interesting_findings.append({
                                "type": "robots_txt",
                                "url": url,
                                "severity": "LOW",
                                "details": f"Found robots.txt with {len(paths)} disallowed paths",
                                "endpoints": paths[:10]  # Limit for display
                            })
                        
                        # Check for sitemap references
                        sitemap_pattern = re.compile(r'Sitemap:\s*(.+)', re.IGNORECASE)
                        for match in sitemap_pattern.finditer(content):
                            sitemap_url = match.group(1).strip()
                            await self._analyze_sitemap(sitemap_url)
                            
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error checking robots.txt: {e}")

    async def _check_sitemaps(self):
        """Check common sitemap locations"""
        sitemap_urls = [
            f"{self.base_url}/sitemap.xml",
            f"{self.base_url}/sitemap_index.xml",
            f"{self.base_url}/sitemap.txt",
            f"{self.base_url}/sitemaps.xml"
        ]
        
        tasks = [self._analyze_sitemap(url) for url in sitemap_urls]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _analyze_sitemap(self, sitemap_url: str):
        """Analyze a sitemap file"""
        try:
            async with self.semaphore:
                async with self.session.get(sitemap_url, headers=self._get_headers()) as response:
                    self.request_count += 1
                    if response.status == 200:
                        content = await response.text()
                        
                        # Extract URLs from XML sitemap
                        url_pattern = re.compile(r'<loc>(.*?)</loc>', re.IGNORECASE)
                        urls = url_pattern.findall(content)
                        
                        if urls:
                            paths = []
                            for url in urls:
                                parsed = urlparse(url)
                                if parsed.path and parsed.path != '/':
                                    paths.append(parsed.path.lstrip('/'))
                            
                            if paths:
                                self.endpoints.extend(paths)
                                self.interesting_findings.append({
                                    "type": "sitemap",
                                    "url": sitemap_url,
                                    "severity": "LOW",
                                    "details": f"Found sitemap with {len(urls)} URLs",
                                    "endpoints": paths[:10]
                                })
                                
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error analyzing sitemap {sitemap_url}: {e}")

    async def _analyze_javascript_files(self):
        """Analyze JavaScript files for API endpoints"""
        js_files = [
            "app.js", "main.js", "bundle.js", "vendor.js", "runtime.js",
            "chunk.js", "index.js", "config.js", "api.js", "ajax.js"
        ]
        
        for js_file in js_files:
            try:
                url = f"{self.base_url}/{js_file}"
                async with self.semaphore:
                    async with self.session.get(url, headers=self._get_headers()) as response:
                        self.request_count += 1
                        if response.status == 200:
                            content = await response.text()
                            
                            # Look for API endpoints in JavaScript
                            api_patterns = [
                                r'["\']([^"\']*api[^"\']*)["\']',
                                r'fetch\(["\']([^"\']+)["\']',
                                r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                                r'\.get\(["\']([^"\']+)["\']',
                                r'\.post\(["\']([^"\']+)["\']',
                                r'url:\s*["\']([^"\']+)["\']'
                            ]
                            
                            endpoints = set()
                            for pattern in api_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    if match.startswith('/'):
                                        endpoints.add(match.lstrip('/'))
                            
                            if endpoints:
                                self.endpoints.extend(list(endpoints))
                                self.interesting_findings.append({
                                    "type": "javascript_endpoints",
                                    "url": url,
                                    "severity": "LOW",
                                    "details": f"Found {len(endpoints)} API endpoints in JavaScript",
                                    "endpoints": list(endpoints)[:10]
                                })
                                
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Error analyzing {js_file}: {e}")
            
            await asyncio.sleep(self.delay)

    async def _analyze_html_pages(self):
        """Analyze HTML pages for API endpoints"""
        pages_to_check = ["", "index", "home", "main", "app"]
        
        for page in pages_to_check:
            try:
                url = f"{self.base_url}/{page}" if page else self.base_url
                logger.info(f"Analyzing HTML page: {page if page else 'index'}")
                
                async with self.semaphore:
                    async with self.session.get(url, headers=self._get_headers()) as response:
                        self.request_count += 1
                        if response.status == 200:
                            content = await response.text()
                            await self._extract_endpoints_from_html(content, url)
                            
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Error analyzing page {page}: {e}")
            
            await asyncio.sleep(self.delay)

    async def _extract_endpoints_from_html(self, content: str, base_url: str):
        """Extract API endpoints from HTML content"""
        endpoints = set()
        
        # Extract from various HTML attributes
        patterns = [
            r'action=["\']([^"\']+)["\']',  # Form actions
            r'href=["\']([^"\']+)["\']',    # Links
            r'src=["\']([^"\']+)["\']',     # Scripts, images
            r'data-url=["\']([^"\']+)["\']', # Data attributes
            r'data-api=["\']([^"\']+)["\']',
            r'data-endpoint=["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/') and not match.startswith('//'):
                    endpoints.add(match.lstrip('/'))
        
        # Look for AJAX calls
        ajax_patterns = [
            r'\$\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']',
            r'\$\.get\(["\']([^"\']+)["\']',
            r'\$\.post\(["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']'
        ]
        
        for pattern in ajax_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/'):
                    endpoints.add(match.lstrip('/'))
        
        if endpoints:
            self.endpoints.extend(list(endpoints))

    async def _check_spa_patterns(self):
        """Check for Single Page Application API patterns"""
        spa_endpoints = [
            "_next/static", "api", "_api", "api/auth", "api/users", "api/data",
            "_nuxt", "api/v1", ".nuxt", "assets/config.json", "api/config",
            "api/app", "app/api", "client/api", "public/api", "static/api",
            "config/api.json", "manifest.json", "service-worker.js"
        ]
        
        for endpoint in spa_endpoints:
            try:
                url = f"{self.base_url}/{endpoint}"
                async with self.semaphore:
                    async with self.session.get(url, headers=self._get_headers()) as response:
                        self.request_count += 1
                        if response.status == 200:
                            logger.info(f"Found SPA endpoint: {endpoint}")
                            self.discovered_endpoints.add(endpoint)
                            self._update_endpoint_info(endpoint, "GET", response.status)
                            
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Error checking SPA endpoint {endpoint}: {e}")
            
            await asyncio.sleep(self.delay)
        
        if self.discovered_endpoints:
            self.interesting_findings.append({
                "type": "spa_endpoints",
                "url": self.base_url,
                "severity": "LOW",
                "details": f"Found {len(self.discovered_endpoints)} SPA endpoints",
                "endpoints": list(self.discovered_endpoints)[:10]
            })

    async def _check_config_files(self):
        """Check for configuration files"""
        config_files = [
            "robots.txt", ".env", ".env.example", "config.json", "settings.json",
            "package.json", "composer.json", "web.config", "app.json",
            ".htaccess", ".htpasswd", "wp-config.php", "config.php"
        ]
        
        found_configs = []
        for config_file in config_files:
            try:
                url = f"{self.base_url}/{config_file}"
                async with self.semaphore:
                    async with self.session.get(url, headers=self._get_headers()) as response:
                        self.request_count += 1
                        if response.status == 200:
                            logger.info(f"Found config file: {config_file}")
                            found_configs.append(config_file)
                            
                            # Check if it's a sensitive file
                            sensitive_files = [".env", ".htpasswd", "wp-config.php", "config.php"]
                            if config_file in sensitive_files:
                                self.interesting_findings.append({
                                    "type": "config_file",
                                    "url": url,
                                    "severity": "HIGH",
                                    "details": f"Sensitive configuration file accessible: {config_file}"
                                })
                            
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Error checking config file {config_file}: {e}")
            
            await asyncio.sleep(self.delay)

    async def _check_api_documentation(self):
        """Check for API documentation endpoints"""
        doc_endpoints = [
            "docs", "documentation", "api-docs", "swagger", "openapi",
            "redoc", "graphql", "graphiql", "playground", "explorer",
            "api/docs", "api/swagger", "api/openapi", "v1/docs",
            "swagger-ui", "swagger.json", "openapi.json", "schema.json"
        ]
        
        for endpoint in doc_endpoints:
            try:
                url = f"{self.base_url}/{endpoint}"
                async with self.semaphore:
                    async with self.session.get(url, headers=self._get_headers()) as response:
                        self.request_count += 1
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for documentation indicators
                            doc_indicators = [
                                "swagger", "openapi", "redoc", "api documentation",
                                "graphql", "playground", "schema"
                            ]
                            
                            if any(indicator in content.lower() for indicator in doc_indicators):
                                logger.info(f"Found documentation link: {url}")
                                self.interesting_findings.append({
                                    "type": "api_documentation",
                                    "url": url,
                                    "severity": "MEDIUM",
                                    "details": f"API documentation found at {endpoint}"
                                })
                                
            except Exception as e:
                
                if self.verbose:
                    logger.debug(f"Error checking documentation endpoint {endpoint}: {e}")
            
            await asyncio.sleep(self.delay)

    async def _discover_endpoints(self):
        """Discover endpoints using wordlist"""
        logger.info(f"Testing {len(self.endpoints)} total endpoints...")
        
        # Create tasks for endpoint discovery
        tasks = []
        for endpoint in self.endpoints:
            task = self._test_endpoint(endpoint)
            tasks.append(task)
        
        # Execute tasks with controlled concurrency
        await self._execute_tasks_with_delay(tasks)

    async def _test_endpoint(self, endpoint: str):
        """Test a single endpoint"""
        try:
            url = f"{self.base_url}/{endpoint}"
            
            async with self.semaphore:
                async with self.session.get(url, headers=self._get_headers()) as response:
                    self.request_count += 1
                    
                    if response.status == 200:
                        logger.info(f"[{response.status}] GET {url}")
                        self.discovered_endpoints.add(endpoint)
                        self._update_endpoint_info(endpoint, "GET", response.status)
                    elif response.status == 401:
                        # Unauthorized might indicate a valid endpoint
                        self.discovered_endpoints.add(endpoint)
                        self._update_endpoint_info(endpoint, "GET", response.status)
                        self.interesting_findings.append({
                            "type": "authentication_required",
                            "url": url,
                            "severity": "MEDIUM",
                            "details": f"Endpoint requires authentication: {endpoint}"
                        })
                    elif response.status == 403:
                        # Forbidden might indicate a valid endpoint
                        self.discovered_endpoints.add(endpoint)
                        self._update_endpoint_info(endpoint, "GET", response.status)
                        self.interesting_findings.append({
                            "type": "access_forbidden",
                            "url": url,
                            "severity": "MEDIUM",
                            "details": f"Access forbidden to endpoint: {endpoint}"
                        })
                    elif response.status == 429:
                        self.rate_limit_hits += 1
                        logger.warning(f"Rate limit hit for {url}")
                        await asyncio.sleep(self.delay * 5)  # Back off
                        
        except asyncio.TimeoutError:
            if self.verbose:
                logger.debug(f"Timeout for endpoint: {endpoint}")
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error testing endpoint {endpoint}: {e}")

    async def _test_http_methods(self):
        """Test different HTTP methods on discovered endpoints"""
        methods = ["HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        
        tasks = []
        for endpoint in self.discovered_endpoints:
            for method in methods:
                task = self._test_method(endpoint, method)
                tasks.append(task)
        
        await self._execute_tasks_with_delay(tasks)

    async def _test_method(self, endpoint: str, method: str):
        """Test a specific HTTP method on an endpoint"""
        try:
            url = f"{self.base_url}/{endpoint}"
            
            async with self.semaphore:
                async with self.session.request(
                    method, url, headers=self._get_headers()
                ) as response:
                    self.request_count += 1
                    
                    if response.status in [200, 201, 202, 204]:
                        logger.info(f"[{response.status}] {method} {url}")
                        self._update_endpoint_info(endpoint, method, response.status)
                        
                        # Check for interesting method responses
                        if method in ["PUT", "DELETE", "PATCH"] and response.status == 200:
                            self.interesting_findings.append({
                                "type": "dangerous_method",
                                "url": url,
                                "severity": "HIGH",
                                "details": f"Endpoint accepts {method} method: {endpoint}"
                            })
                    elif response.status == 405:
                        # Method not allowed is expected
                        pass
                    elif response.status == 429:
                        self.rate_limit_hits += 1
                        await asyncio.sleep(self.delay * 3)
                        
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error testing {method} on {endpoint}: {e}")

    async def _discover_parameters(self):
        """Discover parameters for endpoints"""
        logger.info("Discovering parameters for endpoints...")
        
        tasks = []
        for endpoint in self.discovered_endpoints:
            task = self._test_parameters(endpoint)
            tasks.append(task)
        
        await self._execute_tasks_with_delay(tasks)

    async def _test_parameters(self, endpoint: str):
        """Test parameters on an endpoint"""
        try:
            for param in COMMON_PARAMETERS:
                url = f"{self.base_url}/{endpoint}"
                params = {param: "1"}  # Simple test value
                
                async with self.semaphore:
                    async with self.session.get(
                        url, params=params, headers=self._get_headers()
                    ) as response:
                        self.request_count += 1
                        
                        if response.status == 200:
                            # Check if parameter affects response
                            if await self._parameter_affects_response(response):
                                logger.info(f"Parameter discovered: {endpoint}?{param}=1")
                                self.discovered_parameters.setdefault(endpoint, set()).add(param)
                        
                        await asyncio.sleep(self.delay / 2)  # Faster for parameters
                        
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error testing parameters for {endpoint}: {e}")

    async def _parameter_affects_response(self, response) -> bool:
        """Check if parameter affects the response"""
        try:
            content = await response.text()
            # Simple heuristic: if response contains common parameter indicators
            indicators = ["error", "invalid", "missing", "required", "parameter"]
            return any(indicator in content.lower() for indicator in indicators)
        except:
            return False
    async def _analyze_findings(self):
        """Analyze findings and generate insights"""
        logger.info("Analyzing findings...")
        
        # Analyze endpoint patterns
        await self._analyze_endpoint_patterns()
        
        # Check for GraphQL
        await self._check_graphql()
        
        # Analyze page structure
        logger.info("Analyzing page structure and metadata...")
        await self._analyze_page_structure()

    async def _analyze_endpoint_patterns(self):
        """Analyze discovered endpoint patterns"""
        if not self.discovered_endpoints:
            return
        
        # Check for admin endpoints
        admin_endpoints = [ep for ep in self.discovered_endpoints 
                          if any(admin_word in ep.lower() 
                                for admin_word in ['admin', 'administrator', 'manage', 'control'])]
        
        if admin_endpoints:
            self.interesting_findings.append({
                "type": "admin_endpoints",
                "url": self.base_url,
                "severity": "HIGH",
                "details": f"Found {len(admin_endpoints)} admin-related endpoints",
                "endpoints": admin_endpoints
            })
        
        # Check for API versioning
        versioned_endpoints = [ep for ep in self.discovered_endpoints 
                             if re.search(r'v\d+|version', ep, re.IGNORECASE)]
        
        if versioned_endpoints:
            self.interesting_findings.append({
                "type": "api_versioning",
                "url": self.base_url,
                "severity": "LOW",
                "details": f"Found {len(versioned_endpoints)} versioned API endpoints",
                "endpoints": versioned_endpoints
            })

    async def _check_graphql(self):
        """Check for GraphQL endpoints"""
        graphql_endpoints = ["graphql", "graphiql", "playground", "api/graphql"]
        
        for endpoint in graphql_endpoints:
            try:
                url = f"{self.base_url}/{endpoint}"
                
                # Test with GraphQL introspection query
                introspection_query = {
                    "query": "{ __schema { types { name } } }"
                }
                
                async with self.semaphore:
                    async with self.session.post(
                        url, json=introspection_query, headers=self._get_headers()
                    ) as response:
                        self.request_count += 1
                        
                        if response.status == 200:
                            content = await response.text()
                            if "schema" in content.lower() or "types" in content.lower():
                                logger.info(f"GraphQL endpoint found: {endpoint}")
                                self.interesting_findings.append({
                                    "type": "graphql_endpoint",
                                    "url": url,
                                    "severity": "MEDIUM",
                                    "details": f"GraphQL endpoint with introspection enabled: {endpoint}"
                                })
                                
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Error checking GraphQL endpoint {endpoint}: {e}")
            
            await asyncio.sleep(self.delay)
        
        # Check for GraphQL indicators in discovered endpoints
        graphql_indicators = [ep for ep in self.discovered_endpoints 
                            if 'graphql' in ep.lower()]
        
        if graphql_indicators:
            self.interesting_findings.append({
                "type": "graphql_indicators",
                "url": self.base_url,
                "severity": "LOW",
                "details": f"Found {len(graphql_indicators)} GraphQL-related endpoints",
                "endpoints": graphql_indicators
            })

    async def _analyze_page_structure(self):
        """Analyze page structure and metadata"""
        try:
            async with self.semaphore:
                async with self.session.get(self.base_url, headers=self._get_headers()) as response:
                    self.request_count += 1
                    
                    if response.status == 200:
                        content = await response.text()
                        
                        # Extract meta information
                        meta_patterns = [
                            r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
                            r'<meta[^>]*name=["\']application-name["\'][^>]*content=["\']([^"\']+)["\']',
                            r'<meta[^>]*name=["\']author["\'][^>]*content=["\']([^"\']+)["\']'
                        ]
                        
                        for pattern in meta_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                self.interesting_findings.append({
                                    "type": "meta_information",
                                    "url": self.base_url,
                                    "severity": "LOW",
                                    "details": f"Found meta information: {', '.join(matches)}"
                                })
                        
                        # Check for framework indicators
                        framework_indicators = {
                            "WordPress": ["wp-content", "wp-includes", "wp-admin"],
                            "Drupal": ["drupal", "sites/default", "modules/"],
                            "Joomla": ["joomla", "components/", "modules/"],
                            "Laravel": ["laravel", "_token", "csrf-token"],
                            "Django": ["django", "csrfmiddlewaretoken"],
                            "React": ["react", "reactjs", "_react"],
                            "Angular": ["angular", "ng-", "angularjs"],
                            "Vue": ["vue", "vuejs", "v-"]
                        }
                        
                        for framework, indicators in framework_indicators.items():
                            if any(indicator in content.lower() for indicator in indicators):
                                self.interesting_findings.append({
                                    "type": "framework_detection",
                                    "url": self.base_url,
                                    "severity": "LOW",
                                    "details": f"Detected framework: {framework}"
                                })
                                break
                        
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error analyzing page structure: {e}")

    async def _execute_tasks_with_delay(self, tasks: List):
        """Execute tasks with controlled delay"""
        for i in range(0, len(tasks), self.concurrency):
            batch = tasks[i:i + self.concurrency]
            await asyncio.gather(*batch, return_exceptions=True)
            if i + self.concurrency < len(tasks):
                await asyncio.sleep(self.delay)

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for requests"""
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        headers.update(self.headers)
        return headers

    def _update_endpoint_info(self, endpoint: str, method: str, status_code: int):
        """Update endpoint information"""
        self.endpoint_methods.setdefault(endpoint, set()).add(method)
        self.endpoint_responses.setdefault(endpoint, {})[method] = status_code

    def _generate_reports(self):
        """Generate both JSON and HTML reports"""
        logger.info("Generating reports...")
        
        # Calculate scan statistics
        scan_duration = time.time() - self.start_time
        
        report = {
            "target": self.base_url,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration": f"{scan_duration:.2f} seconds",
            "total_requests": self.request_count,
            "rate_limit_hits": self.rate_limit_hits,
            "discovered_endpoints": len(self.discovered_endpoints),
            "endpoints": {
                endpoint: {
                    "methods": list(self.endpoint_methods[endpoint]),
                    "parameters": list(self.discovered_parameters.get(endpoint, set())),
                    "responses": dict(self.endpoint_responses.get(endpoint, {}))
                }
                for endpoint in self.discovered_endpoints
            },
            "interesting_findings": self.interesting_findings}
        
        # Generate JSON report
        self._generate_json_report(report)
        
        # Generate HTML report
        self._generate_html_report(report)
        
        # Generate Analysis webpage
        self._generate_analysis_webpage(report)
        
        # Print summary
        self._print_summary(report)

    def _ensure_output_directories(self, target_name):
        """Ensure output directories exist for the target"""
        import os
        base_dir = f"results/{target_name}"
        # Create base results directory structure
        directories = [
            base_dir,
            f"{base_dir}/json",
            f"{base_dir}/html",
            f"{base_dir}/analysis",]
        
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                logger.info(f"Created directory: {directory}")
        
        return base_dir

    def _create_filename_from_url(self, url):
        """Create a safe filename from URL"""
        import re
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            
            # Clean up the domain name
            domain = re.sub(r'^(https?://)?', '', domain)
            domain = re.sub(r'^(www\.)?', '', domain)
            domain = re.sub(r':\d+', '', domain)
            
            # Create safe filename
            filename = re.sub(r'[^\w\-_.]', '_', domain)
            filename = re.sub(r'_+', '_', filename).strip('_')
            
            return filename or "unknown_target"
            
        except Exception as e:
            logger.warning(f"Could not create filename from URL {url}: {str(e)}")
            return "unknown_target"

    def _generate_json_report(self, report):
        """Generate JSON report"""
        # Create filename from target URL
        filename = self._create_filename_from_url(report['target'])
        
        # Ensure output directories exist
        base_dir = self._ensure_output_directories(filename)
        json_path = f"{base_dir}/json/{filename}.json"
        
        try:
            with open(json_path, "w", encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON report saved to: {json_path}")
        except Exception as e:
            logger.error(f"Failed to save JSON report: {str(e)}")

    def _generate_html_report(self, report):
        """Generate HTML report"""
        # Create filename from target URL
        filename = self._create_filename_from_url(report['target'])
        
        # Ensure output directories exist
        base_dir = self._ensure_output_directories(filename)
        html_path = f"{base_dir}/html/{filename}.html"
        
        try:
            html_content = self._create_html_report(report)
            with open(html_path, "w", encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report saved to: {html_path}")
        except Exception as e:
            logger.error(f"Failed to save HTML report: {str(e)}")


    def _create_html_report(self, report):
        """Create HTML report content"""
        html_template = """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>API Endpoint Discovery Report</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            html, body {{
                height: 100%;
                overflow-x: auto;
                overflow-y: auto;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f5f5f5;
                min-height: 100vh;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                min-height: 100vh;
            }}
            
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            
            .header h1 {{
                font-size: 2.5em;
                margin-bottom: 10px;
            }}
            
            .header .subtitle {{
                font-size: 1.2em;
                opacity: 0.9;
            }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            
            .stat-card {{
                background: white;
                padding: 25px;
                border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-align: center;
            }}
            
            .stat-card h3 {{
                font-size: 2em;
                color: #667eea;
                margin-bottom: 10px;
            }}
            
            .stat-card p {{
                color: #666;
                font-size: 1.1em;
            }}
            
            .section {{
                background: white;
                margin-bottom: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                overflow: visible;
            }}
            
            .section-header {{
                background: #f8f9fa;
                padding: 20px;
                border-bottom: 1px solid #e9ecef;
            }}
            
            .section-header h2 {{
                color: #495057;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .section-content {{
                padding: 20px;
                max-height: none;
                overflow: visible;
            }}
            
            .endpoint-list {{
                display: grid;
                gap: 15px;
                max-height: none;
                overflow: visible;
            }}
            
            .endpoint-item {{
                border: 1px solid #e9ecef;
                border-radius: 8px;
                padding: 15px;
                background: #f8f9fa;
            }}
            
            .endpoint-url {{
                font-family: 'Courier New', monospace;
                font-weight: bold;
                color: #28a745;
                margin-bottom: 10px;
                word-break: break-all;
                overflow-wrap: break-word;
            }}
            
            .endpoint-methods {{
                display: flex;
                gap: 5px;
                margin-bottom: 10px;
                flex-wrap: wrap;
            }}
            
            .method-badge {{
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                font-weight: bold;
                color: white;
            }}
            
            .method-GET {{ background-color: #28a745; }}
            .method-POST {{ background-color: #007bff; }}
            .method-PUT {{ background-color: #ffc107; color: #000; }}
            .method-DELETE {{ background-color: #dc3545; }}
            .method-PATCH {{ background-color: #6f42c1; }}
            .method-OPTIONS {{ background-color: #6c757d; }}
            .method-HEAD {{ background-color: #17a2b8; }}
            
            .parameters {{
                margin-top: 10px;
            }}
            
            .parameter-tag {{
                display: inline-block;
                background: #e9ecef;
                color: #495057;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 0.8em;
                margin-right: 5px;
                margin-bottom: 3px;
            }}
            
            .finding-item {{
                border-left: 4px solid #007bff;
                padding: 15px;
                margin-bottom: 15px;
                background: #f8f9fa;
                border-radius: 0 8px 8px 0;
                word-wrap: break-word;
            }}
            
            .finding-item.severity-CRITICAL {{
                border-left-color: #dc3545;
                background: #f8d7da;
            }}
            
            .finding-item.severity-HIGH {{
                border-left-color: #fd7e14;
                background: #fff3cd;
            }}
            
            .finding-item.severity-MEDIUM {{
                border-left-color: #ffc107;
                background: #fff3cd;
            }}
            
            .finding-item.severity-LOW {{
                border-left-color: #28a745;
                background: #d4edda;
            }}
            
            .severity-badge {{
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                font-weight: bold;
                color: white;
                margin-left: 10px;
            }}
            
            .severity-CRITICAL {{ background-color: #dc3545; }}
            .severity-HIGH {{ background-color: #fd7e14; }}
            .severity-MEDIUM {{ background-color: #ffc107; color: #000; }}
            .severity-LOW {{ background-color: #28a745; }}

            .no-data {{
                text-align: center;
                color: #6c757d;
                font-style: italic;
                padding: 40px;
            }}
            
            .icon {{
                width: 20px;
                height: 20px;
                fill: currentColor;
                transition: transform 0.3s ease;
            }}
            
            .collapsible {{
                cursor: pointer;
                user-select: none;
            }}
            
            .collapsible:hover {{
                background-color: #e9ecef;
            }}
            
            .collapsible-content {{
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.3s ease;
            }}
            
            .collapsible-content.active {{
                max-height: none;
                overflow: visible;
            }}
            
            @media (max-width: 768px) {{
                .container {{
                    padding: 10px;
                }}
                
                .header h1 {{
                    font-size: 2em;
                }}
                
                .stats-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .endpoint-methods {{
                    flex-wrap: wrap;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 API Endpoint Discovery Report</h1>
                <div class="subtitle">
                    Target: {target}<br>
                    Scan Date: {scan_date}<br>
                    Duration: {scan_duration}
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{discovered_endpoints}</h3>
                    <p>Endpoints Discovered</p>
                </div>
                <div class="stat-card">
                    <h3>{total_requests}</h3>
                    <p>Total Requests</p>
                </div>
                <div class="stat-card">
                    <h3>{interesting_findings_count}</h3>
                    <p>Interesting Findings</p>
                </div>
            </div>
            
            {endpoints_section}
            
            {findings_section}
            
        </div>
        
        <script>
            // Make sections collapsible with better height handling
            document.querySelectorAll('.collapsible').forEach(function(element) {{
                element.addEventListener('click', function() {{
                    const content = this.nextElementSibling;
                    const isActive = content.classList.contains('active');
                    
                    if (isActive) {{
                        // Collapse
                        content.style.maxHeight = content.scrollHeight + 'px';
                        setTimeout(() => {{
                            content.style.maxHeight = '0px';
                        }}, 10);
                        content.classList.remove('active');
                    }} else {{
                        // Expand
                        content.classList.add('active');
                        content.style.maxHeight = content.scrollHeight + 'px';
                        
                        // Remove max-height after transition completes
                        setTimeout(() => {{
                            if (content.classList.contains('active')) {{
                                content.style.maxHeight = 'none';
                            }}
                        }}, 300);
                    }}
                    
                    const icon = this.querySelector('.icon');
                    if (icon) {{
                        if (isActive) {{
                            icon.style.transform = 'rotate(0deg)';
                        }} else {{
                            icon.style.transform = 'rotate(90deg)';
                        }}
                    }}
                }});
            }});
            
            // Auto-expand first section
            const firstContent = document.querySelector('.collapsible-content');
            if (firstContent) {{
                firstContent.classList.add('active');
                firstContent.style.maxHeight = 'none';
                const firstIcon = document.querySelector('.icon');
                if (firstIcon) {{
                    firstIcon.style.transform = 'rotate(90deg)';
                }}
            }}
            
            // Ensure page can scroll to show all content
            document.body.style.minHeight = '100vh';
        </script>
    </body>
    </html>"""
        
        # Generate endpoints section
        endpoints_html = ""
        if report['endpoints']:
            endpoints_items = []
            for endpoint, details in report['endpoints'].items():
                methods_html = ""
                for method in details['methods']:
                    methods_html += f'<span class="method-badge method-{method}">{method}</span>'
                
                parameters_html = ""
                if details['parameters']:
                    parameters_html = '<div class="parameters"><strong>Parameters:</strong><br>'
                    for param in details['parameters']:
                        parameters_html += f'<span class="parameter-tag">{param}</span>'
                    parameters_html += '</div>'
                
                responses_html = ""
                if details['responses']:
                    responses_html = '<div class="responses"><strong>Response Codes:</strong> '
                    for method, status in details['responses'].items():
                        responses_html += f'{method}:{status} '
                    responses_html += '</div>'
                
                endpoints_items.append(f"""
                <div class="endpoint-item">
                    <div class="endpoint-url">/{endpoint}</div>
                    <div class="endpoint-methods">{methods_html}</div>
                    {parameters_html}
                    {responses_html}
                </div>
                """)
            
            endpoints_html = f"""
            <div class="section">
                <div class="section-header collapsible">
                    <h2>
                        <svg class="icon" viewBox="0 0 24 24">
                            <path d="M8.59,16.58L13.17,12L8.59,7.41L10,6L16,12L10,18L8.59,16.58Z"/>
                        </svg>
                        Discovered Endpoints ({len(report['endpoints'])})
                    </h2>
                </div>
                <div class="section-content collapsible-content">
                    <div class="endpoint-list">
                        {''.join(endpoints_items)}
                    </div>
                </div>
            </div>
            """
        else:
            endpoints_html = f"""
            <div class="section">
                <div class="section-header">
                    <h2>🔗 Discovered Endpoints</h2>
                </div>
                <div class="section-content">
                    <div class="no-data">No endpoints discovered</div>
                </div>
            </div>
            """
        
        # Generate interesting findings section
        findings_html = ""
        if report['interesting_findings']:
            findings_items = []
            for finding in report['interesting_findings']:
                severity_class = f"severity-{finding['severity']}"
                endpoints_list = ""
                if finding.get("endpoints"):
                    endpoints_list = f'<div style="margin-top: 8px;"><strong>Endpoints:</strong> {", ".join(finding.get("endpoints", [])[:10])}</div>'
                
                findings_items.append(f"""
                <div class="finding-item {severity_class}">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <strong>{finding['type'].replace('_', ' ').title()}</strong>
                        <span class="severity-badge {severity_class}">{finding['severity']}</span>
                    </div>
                    <div style="margin-bottom: 8px;"><strong>URL:</strong> <code>{finding['url']}</code></div>
                    <div><strong>Details:</strong> {finding['details']}</div>
                    {endpoints_list}
                </div>
                """)
            
            findings_html = f"""
            <div class="section">
                <div class="section-header collapsible">
                    <h2>
                        <svg class="icon" viewBox="0 0 24 24">
                            <path d="M8.59,16.58L13.17,12L8.59,7.41L10,6L16,12L10,18L8.59,16.58Z"/>
                        </svg>
                        Interesting Findings ({len(report['interesting_findings'])})
                    </h2>
                </div>
                <div class="section-content collapsible-content">
                    {''.join(findings_items)}
                </div>
            </div>
            """
        else:
            findings_html = f"""
            <div class="section">
                <div class="section-header">
                    <h2>🔍 Interesting Findings</h2>
                </div>
                <div class="section-content">
                    <div class="no-data">No interesting findings discovered</div>
                </div>
            </div>
            """

        
        # Fill in the template
        return html_template.format(
            target=report['target'],
            scan_date=report['scan_date'],
            scan_duration=report['scan_duration'],
            discovered_endpoints=report['discovered_endpoints'],
            total_requests=report['total_requests'],
            interesting_findings_count=len(report['interesting_findings']),
            endpoints_section=endpoints_html,
            findings_section=findings_html,
        )

    def _generate_analysis_webpage(self, report):
        filename = self._create_filename_from_url(report['target'])
        # Ensure output directories exist
        base_dir = self._ensure_output_directories(filename)
        """Generate a comprehensive analysis webpage"""
        filename = self._create_filename_from_url(report['target'])
        analysis_html_path = f"{base_dir}/analysis/{filename}analysis.html"
        
        # Analyze the data
        analysis = self._perform_deep_analysis(report)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Analysis - {report['target']}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .main-header {{
            text-align: center;
            color: white;
            margin-bottom: 40px;
            padding: 40px 0;
        }}
        
        .main-header h1 {{
            font-size: 3.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .main-header .subtitle {{
            font-size: 1.3em;
            opacity: 0.9;
        }}
        
        .analysis-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin-bottom: 40px;
        }}
        
        .analysis-card {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }}
        
        .analysis-card h2 {{
            color: #4a5568;
            margin-bottom: 20px;
            font-size: 1.5em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .metric {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .metric:last-child {{
            border-bottom: none;
        }}
        
        .metric-label {{
            font-weight: 500;
            color: #4a5568;
        }}
        
        .metric-value {{
            font-weight: bold;
            font-size: 1.1em;
        }}
        
        .risk-high {{ color: #e53e3e; }}
        .risk-medium {{ color: #dd6b20; }}
        .risk-low {{ color: #38a169; }}
        .risk-info {{ color: #3182ce; }}
        
        .progress-bar {{
            width: 100%;
            height: 8px;
            background-color: #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 5px;
        }}
        
        .progress-fill {{
            height: 100%;
            transition: width 0.3s ease;
        }}
        
        .progress-high {{ background-color: #e53e3e; }}
        .progress-medium {{ background-color: #dd6b20; }}
        .progress-low {{ background-color: #38a169; }}
        
        .recommendations {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            margin-bottom: 30px;
        }}
        
        .recommendations h2 {{
            color: #4a5568;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .recommendation-item {{
            background: #f7fafc;
            border-left: 4px solid #3182ce;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
        }}
        
        .recommendation-item.high {{
            border-left-color: #e53e3e;
            background: #fed7d7;
        }}
        
        .recommendation-item.medium {{
            border-left-color: #dd6b20;
            background: #feebc8;
        }}
        
        .recommendation-title {{
            font-weight: bold;
            margin-bottom: 8px;
            color: #2d3748;
        }}
        
        .recommendation-desc {{
            color: #4a5568;
            line-height: 1.5;
        }}
        
        .chart-container {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .pie-chart {{
            width: 200px;
            height: 200px;
            margin: 20px auto;
        }}
        
        .endpoint-analysis {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .endpoint-card {{
            background: #f7fafc;
            border-radius: 8px;
            padding: 15px;
            border-left: 4px solid #3182ce;
        }}
        
        .endpoint-card.suspicious {{
            border-left-color: #e53e3e;
            background: #fed7d7;
        }}
        
        .endpoint-card.interesting {{
            border-left-color: #dd6b20;
            background: #feebc8;
        }}
        
        .endpoint-path {{
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #2d3748;
            margin-bottom: 8px;
        }}
        
        .endpoint-details {{
            font-size: 0.9em;
            color: #4a5568;
        }}
        
        .timeline {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }}
        
        .timeline-item {{
            display: flex;
            align-items: center;
            padding: 15px 0;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .timeline-item:last-child {{
            border-bottom: none;
        }}
        
        .timeline-icon {{
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 15px;
            color: white;
            font-weight: bold;
        }}
        
        .timeline-icon.phase1 {{ background-color: #3182ce; }}
        .timeline-icon.phase2 {{ background-color: #38a169; }}
        .timeline-icon.phase3 {{ background-color: #dd6b20; }}
        .timeline-icon.phase4 {{ background-color: #9f7aea; }}
        
        .timeline-content h4 {{
            color: #2d3748;
            margin-bottom: 5px;
        }}
        
        .timeline-content p {{
            color: #4a5568;
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .main-header h1 {{
                font-size: 2.5em;
            }}
            
            .analysis-grid {{
                grid-template-columns: 1fr;
            }}
            
            .endpoint-analysis {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="main-header">
            <h1>🔍 API Security Analysis</h1>
            <div class="subtitle">
                Comprehensive analysis of {report['target']}<br>
                Generated on {report['scan_date']}
            </div>
        </div>
        
        <div class="analysis-grid">
            <div class="analysis-card">
                <h2>📊 Scan Overview</h2>
                <div class="metric">
                    <span class="metric-label">Target Domain</span>
                    <span class="metric-value">{analysis['domain']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Scan Duration</span>
                    <span class="metric-value">{report['scan_duration']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Total Requests</span>
                    <span class="metric-value">{report['total_requests']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Success Rate</span>
                    <span class="metric-value risk-{analysis['success_rate_risk']}">{analysis['success_rate']}%</span>
                </div>
            </div>
            
            <div class="analysis-card">
                <h2>🎯 Discovery Results</h2>
                <div class="metric">
                    <span class="metric-label">Endpoints Found</span>
                    <span class="metric-value risk-{analysis['endpoints_risk']}">{report['discovered_endpoints']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">HTTP Methods</span>
                    <span class="metric-value">{analysis['unique_methods']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Parameters Found</span>
                    <span class="metric-value">{analysis['total_parameters']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Interesting Findings</span>
                    <span class="metric-value risk-{analysis['findings_risk']}">{len(report['interesting_findings'])}</span>
                </div>
            </div>
            
            <div class="analysis-card">
                <h2>⚠️ Security Assessment</h2>
                <div class="metric">
                    <span class="metric-label">Overall Risk Level</span>
                    <span class="metric-value risk-{analysis['overall_risk'].lower()}">{analysis['overall_risk']}</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill progress-{analysis['overall_risk'].lower()}" style="width: {analysis['risk_percentage']}%"></div>
                </div>
                <div class="metric">
                    <span class="metric-label">Critical Issues</span>
                    <span class="metric-value risk-high">{analysis['critical_count']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">High Risk Items</span>
                    <span class="metric-value risk-high">{analysis['high_count']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Medium Risk Items</span>
                    <span class="metric-value risk-medium">{analysis['medium_count']}</span>
                </div>
            </div>
            
            <div class="analysis-card">
                <h2>🔧 Technical Details</h2>
                <div class="metric">
                    <span class="metric-label">Server Technology</span>
                    <span class="metric-value">{analysis['server_tech']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Framework Detected</span>
                    <span class="metric-value">{analysis['framework']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">API Patterns</span>
                    <span class="metric-value">{analysis['api_patterns']}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Authentication Found</span>
                    <span class="metric-value risk-{analysis['auth_risk']}">{analysis['auth_indicators']}</span>
                </div>
            </div>
        </div>
        
        <div class="recommendations">
            <h2>🎯 Security Recommendations</h2>
            {analysis['recommendations_html']}
        </div>
        
        <div class="chart-container">
            <h2>📈 Endpoint Distribution Analysis</h2>
            <div class="endpoint-analysis">
                {analysis['endpoint_analysis_html']}
            </div>
        </div>
        
        <div class="timeline">
            <h2>🕐 Scan Timeline</h2>
            <div class="timeline-item">
                <div class="timeline-icon phase1">1</div>
                <div class="timeline-content">
                    <h4>Information Disclosure Phase</h4>
                    <p>Analyzed robots.txt, sitemaps, and configuration files. Found {analysis['info_disclosure_count']} disclosure sources.</p>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-icon phase2">2</div>
                <div class="timeline-content">
                    <h4>Endpoint Discovery Phase</h4>
                    <p>Discovered {report['discovered_endpoints']} endpoints using wordlist and pattern matching techniques.</p>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-icon phase3">3</div>
                <div class="timeline-content">
                    <h4>Method Testing Phase</h4>
                    <p>Tested {analysis['unique_methods']} HTTP methods across discovered endpoints.</p>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-icon phase4">4</div>
                <div class="timeline-content">
                    <h4>Parameter Discovery Phase</h4>
                    <p>Identified {analysis['total_parameters']} parameters that could be used for further testing.</p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Add some interactive elements
        document.addEventListener('DOMContentLoaded', function() {{
            // Animate progress bars
            const progressBars = document.querySelectorAll('.progress-fill');
            progressBars.forEach(bar => {{
                const width = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => {{
                    bar.style.width = width;
                }}, 500);
            }});
            
            // Add hover effects to cards
            const cards = document.querySelectorAll('.analysis-card, .endpoint-card');
            cards.forEach(card => {{
                card.addEventListener('mouseenter', function() {{
                    this.style.transform = 'translateY(-5px)';
                    this.style.transition = 'transform 0.3s ease';
                }});
                
                card.addEventListener('mouseleave', function() {{
                    this.style.transform = 'translateY(0)';
                }});
            }});
        }});
    </script>
</body>
</html>"""
        
        try:
            with open(analysis_html_path, "w", encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"{COLORS['green']}Analysis webpage saved to: {analysis_html_path}{COLORS['reset']}")
        except Exception as e:
            logger.error(f"Failed to save analysis webpage: {str(e)}")

    def _perform_deep_analysis(self, report):
        """Perform deep analysis of the scan results"""
        from urllib.parse import urlparse
        
        parsed_url = urlparse(report['target'])
        domain = parsed_url.netloc
        
        # Calculate success rate
        total_endpoints_tested = len(self.endpoints)
        discovered = report['discovered_endpoints']
        success_rate = (discovered / total_endpoints_tested * 100) if total_endpoints_tested > 0 else 0
        
        # Analyze HTTP methods
        all_methods = set()
        for endpoint_data in report['endpoints'].values():
            all_methods.update(endpoint_data['methods'])
        
        # Count parameters
        total_parameters = sum(len(endpoint_data['parameters']) for endpoint_data in report['endpoints'].values())
        
        # Analyze findings by severity
        critical_count = sum(1 for finding in report['interesting_findings'] if finding['severity'] == 'CRITICAL')
        high_count = sum(1 for finding in report['interesting_findings'] if finding['severity'] == 'HIGH')
        medium_count = sum(1 for finding in report['interesting_findings'] if finding['severity'] == 'MEDIUM')
        low_count = sum(1 for finding in report['interesting_findings'] if finding['severity'] == 'LOW')
        
        # Determine overall risk
        if critical_count > 0:
            overall_risk = "CRITICAL"
            risk_percentage = 90
        elif high_count > 2:
            overall_risk = "HIGH"
            risk_percentage = 75
        elif high_count > 0 or medium_count > 3:
            overall_risk = "MEDIUM"
            risk_percentage = 50
        else:
            overall_risk = "LOW"
            risk_percentage = 25
        
        # Detect server technology and framework
        server_tech = "Unknown"
        framework = "Unknown"
        api_patterns = []
        auth_indicators = "No"
        
        # Analyze endpoint patterns
        endpoint_paths = list(report['endpoints'].keys())
        
        # Check for common frameworks
        if any('admin' in path.lower() for path in endpoint_paths):
            framework = "CMS (Joomla/WordPress/Drupal)"
            api_patterns.append("CMS")
        
        if any(path in ['api', '_api', 'api/v1'] for path in endpoint_paths):
            api_patterns.append("REST API")
        
        if any('graphql' in path.lower() for path in endpoint_paths):
            api_patterns.append("GraphQL")
        
        # Check for authentication indicators
        auth_keywords = ['auth', 'login', 'token', 'oauth', 'jwt']
        if any(any(keyword in path.lower() for keyword in auth_keywords) for path in endpoint_paths):
            auth_indicators = "Yes"
        
        # Generate recommendations
        recommendations = []
        
        if critical_count > 0:
            recommendations.append({
                "title": "🚨 Critical Security Issues Detected",
                "description": f"Found {critical_count} critical security issues that require immediate attention. Review exposed configuration files and sensitive endpoints.",
                "priority": "high"
            })
        
        if high_count > 0:
            recommendations.append({
                "title": "⚠️ High Risk Endpoints Found",
                "description": f"Discovered {high_count} high-risk endpoints. Implement proper access controls and authentication mechanisms.",
                "priority": "high"
            })
        
        if discovered > 10:
            recommendations.append({
                "title": "🔒 Large Attack Surface",
                "description": f"Found {discovered} accessible endpoints. Consider implementing API gateway and rate limiting to reduce attack surface.",
                "priority": "medium"
            })
        
        if auth_indicators == "Yes":
            recommendations.append({
                "title": "🔐 Authentication Endpoints Detected",
                "description": "Authentication-related endpoints found. Ensure proper security measures like rate limiting, CAPTCHA, and strong password policies are implemented.",
                "priority": "medium"
            })
        
        if total_parameters > 20:
            recommendations.append({
                "title": "📝 Multiple Parameters Discovered",
                "description": f"Found {total_parameters} parameters across endpoints. Implement input validation and sanitization to prevent injection attacks.",
                "priority": "medium"
            })
        
        recommendations.append({
            "title": "🛡️ General Security Hardening",
            "description": "Implement security headers, HTTPS enforcement, and regular security audits. Consider implementing Web Application Firewall (WAF).",
            "priority": "low"
        })
        
        # Generate recommendations HTML
        recommendations_html = ""
        for rec in recommendations:
            priority_class = rec['priority']
            recommendations_html += f"""
            <div class="recommendation-item {priority_class}">
                <div class="recommendation-title">{rec['title']}</div>
                <div class="recommendation-desc">{rec['description']}</div>
            </div>
            """
        
        # Generate endpoint analysis HTML
        endpoint_analysis_html = ""
        suspicious_endpoints = []
        interesting_endpoints = []
        
        for endpoint, details in report['endpoints'].items():
            if any(keyword in endpoint.lower() for keyword in ['admin', 'config', 'backup', 'test', 'debug']):
                suspicious_endpoints.append(endpoint)
            elif len(details['methods']) > 4 or len(details['parameters']) > 5:
                interesting_endpoints.append(endpoint)
        
        # Add suspicious endpoints
        for endpoint in suspicious_endpoints[:6]:  # Limit to 6
            details = report['endpoints'][endpoint]
            endpoint_analysis_html += f"""
            <div class="endpoint-card suspicious">
                <div class="endpoint-path">/{endpoint}</div>
                <div class="endpoint-details">
                    🚨 Suspicious endpoint - {len(details['methods'])} methods, {len(details['parameters'])} parameters
                </div>
            </div>
            """
        
        # Add interesting endpoints
        for endpoint in interesting_endpoints[:6]:  # Limit to 6
            details = report['endpoints'][endpoint]
            endpoint_analysis_html += f"""
            <div class="endpoint-card interesting">
                <div class="endpoint-path">/{endpoint}</div>
                <div class="endpoint-details">
                    🔍 High activity endpoint - {len(details['methods'])} methods, {len(details['parameters'])} parameters
                </div>
            </div>
            """
        
        # Add normal endpoints
        normal_endpoints = [ep for ep in report['endpoints'].keys() 
                          if ep not in suspicious_endpoints and ep not in interesting_endpoints]
        for endpoint in normal_endpoints[:4]:  # Limit to 4
            details = report['endpoints'][endpoint]
            endpoint_analysis_html += f"""
            <div class="endpoint-card">
                <div class="endpoint-path">/{endpoint}</div>
                <div class="endpoint-details">
                    📄 Standard endpoint - {len(details['methods'])} methods, {len(details['parameters'])} parameters
                </div>
            </div>
            """
        
        return {
            'domain': domain,
            'success_rate': round(success_rate, 1),
            'success_rate_risk': 'high' if success_rate > 70 else 'medium' if success_rate > 40 else 'low',
            'unique_methods': len(all_methods),
            'total_parameters': total_parameters,
            'endpoints_risk': 'high' if discovered > 15 else 'medium' if discovered > 8 else 'low',
            'findings_risk': 'high' if len(report['interesting_findings']) > 3 else 'medium' if len(report['interesting_findings']) > 1 else 'low',
            'overall_risk': overall_risk,
            'risk_percentage': risk_percentage,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'server_tech': server_tech,
            'framework': framework,
            'api_patterns': ', '.join(api_patterns) if api_patterns else 'Standard Web',
            'auth_indicators': auth_indicators,
            'auth_risk': 'medium' if auth_indicators == "Yes" else 'low',
            'recommendations_html': recommendations_html,
            'endpoint_analysis_html': endpoint_analysis_html,
            'info_disclosure_count': len([f for f in report['interesting_findings'] if 'config' in f['type'] or 'robots' in f['type']])
        }

    def _print_summary(self, report):
        """Print scan summary"""
        print(f"\n{COLORS['bold']}{COLORS['green']}{'='*60}{COLORS['reset']}")
        print(f"{COLORS['bold']}{COLORS['green']}API ENDPOINT DISCOVERY SUMMARY{COLORS['reset']}")
        print(f"{COLORS['bold']}{COLORS['green']}{'='*60}{COLORS['reset']}")
        
        print(f"\n{COLORS['cyan']}Target:{COLORS['reset']} {report['target']}")
        print(f"{COLORS['cyan']}Scan Duration:{COLORS['reset']} {report['scan_duration']}")
        print(f"{COLORS['cyan']}Total Requests:{COLORS['reset']} {report['total_requests']}")
        print(f"{COLORS['cyan']}Rate Limit Hits:{COLORS['reset']} {report['rate_limit_hits']}")
        
        print(f"\n{COLORS['yellow']}📊 DISCOVERY RESULTS:{COLORS['reset']}")
        print(f"  • Endpoints Discovered: {COLORS['green']}{report['discovered_endpoints']}{COLORS['reset']}")
        print(f"  • Interesting Findings: {COLORS['yellow']}{len(report['interesting_findings'])}{COLORS['reset']}")
        
        # Show top endpoints
        if report['endpoints']:
            print(f"\n{COLORS['blue']}🔗 TOP DISCOVERED ENDPOINTS:{COLORS['reset']}")
            for i, (endpoint, details) in enumerate(list(report['endpoints'].items())[:10]):
                methods = ', '.join(details['methods'])
                params = len(details['parameters'])
                print(f"  {i+1:2d}. /{endpoint}")
                print(f"      Methods: {COLORS['green']}{methods}{COLORS['reset']}")
                if params > 0:
                    print(f"      Parameters: {COLORS['yellow']}{params}{COLORS['reset']}")
        
        # Show critical findings
        critical_findings = [f for f in report['interesting_findings'] if f['severity'] in ['CRITICAL', 'HIGH']]
        if critical_findings:
            print(f"\n{COLORS['red']}⚠️  CRITICAL FINDINGS:{COLORS['reset']}")
            for finding in critical_findings[:5]:
                print(f"  • {finding['type'].replace('_', ' ').title()}")
                print(f"    Severity: {COLORS['red']}{finding['severity']}{COLORS['reset']}")
                print(f"    Details: {finding['details']}")
        
        print(f"\n{COLORS['green']}📁 Reports generated in 'results/' directory{COLORS['reset']}")
        print(f"{COLORS['bold']}{COLORS['green']}{'='*60}{COLORS['reset']}\n")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Advanced API Endpoint Discovery Tool v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://api.example.com -c 20 -d 0.1
  %(prog)s -u https://example.com -w custom_wordlist.txt -v
  %(prog)s -u https://example.com -H "Authorization: Bearer token"
  %(prog)s -u https://example.com --proxy http://127.0.0.1:8080
        """
    )
    
    # Required arguments
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL (e.g., https://example.com)"
    )
    
    # Optional arguments
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=10,
        help="Number of concurrent requests (default: 10)"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.1,
        help="Delay between requests in seconds (default: 0.1)"
    )
    
    parser.add_argument(
        "-w", "--wordlist",
        help="Path to custom wordlist file"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: auto-generated)"
    )
    
    parser.add_argument(
        "-H", "--header",
        action="append",
        help="Custom header (can be used multiple times)"
    )
    
    parser.add_argument(
        "--cookie",
        help="Cookie string (e.g., 'session=abc123')"
    )
    
    parser.add_argument(
        "--auth",
        help="Basic authentication (username:password)"
    )
    
    parser.add_argument(
        "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="Maximum recursion depth for endpoint discovery (default: 3)"
    )
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        logger.error("URL must start with http:// or https://")
        return
    
    # Parse headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
            else:
                logger.warning(f"Invalid header format: {header}")
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    
    # Parse authentication
    auth = None
    if args.auth:
        if ':' in args.auth:
            username, password = args.auth.split(':', 1)
            auth = (username, password)
        else:
            logger.warning("Invalid auth format. Use username:password")
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create discovery instance
    discovery = ApiEndpointDiscovery(
        base_url=args.url,
        concurrency=args.concurrency,
        timeout=args.timeout,
        delay=args.delay,
        headers=headers,
        cookies=cookies,
        auth=auth,
        proxy=args.proxy,
        wordlist_path=args.wordlist,
        output_file=args.output,
        verbose=args.verbose,
        max_depth=args.max_depth,
    )
    
    try:
        # Run discovery
        asyncio.run(discovery.discover())
    except KeyboardInterrupt:
        logger.info(f"\n{COLORS['yellow']}Scan interrupted by user{COLORS['reset']}")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()


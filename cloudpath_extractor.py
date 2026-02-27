#!/usr/bin/env python3
"""
Cloudpath Enrollment System - Full Configuration Extractor

Extracts 100% of configuration details from a Cloudpath deployment via REST API
and outputs a comprehensive nested JSON file.

Supports Cloudpath 5.11+ using the /admin/publicApi endpoint with JWT authentication.
"""

import os
import sys
import json
import logging
import glob
import time
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass, field

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv

# Suppress SSL warnings when verify_ssl=False
disable_warnings(InsecureRequestWarning)


def setup_logging(max_log_files: int = 5) -> logging.Logger:
    """
    Configure logging with rotating log files.

    Creates a 'logs' directory and maintains only the last N log files.
    Each run creates a new timestamped log file.
    """
    # Get script directory and create logs folder
    script_dir = Path(__file__).parent
    logs_dir = script_dir / 'logs'
    logs_dir.mkdir(exist_ok=True)

    # Clean up old log files, keeping only the most recent (max_log_files - 1)
    # to make room for the new one
    existing_logs = sorted(logs_dir.glob('cloudpath_*.log'), key=os.path.getmtime)
    while len(existing_logs) >= max_log_files:
        oldest = existing_logs.pop(0)
        try:
            oldest.unlink()
        except OSError:
            pass

    # Create new log file with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = logs_dir / f'cloudpath_{timestamp}.log'

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding='utf-8')
        ]
    )

    logger = logging.getLogger(__name__)
    logger.info(f"Log file: {log_file}")

    return logger


# Initialize logging
logger = setup_logging(max_log_files=5)


@dataclass
class CloudpathConfig:
    """Configuration for Cloudpath API connection."""
    fqdn: str
    username: str
    password: str
    api_key: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = 30
    page_size: int = 100
    dpsk_pool_id: Optional[str] = None  # Filter to specific DPSK pool by ID/GUID
    ssid_match: Optional[str] = None  # Filter DPSKs to those with this string in ssidList
    name_match: Optional[str] = None  # Filter DPSKs to those with this string in name
    name_match_strip: Optional[str] = None  # Filter by name AND strip matched string from output
    full_details: bool = False  # Fetch full details for each DPSK (slower)

    @property
    def base_url(self) -> str:
        return f"https://{self.fqdn}/admin/publicApi"

    @classmethod
    def from_env(cls) -> 'CloudpathConfig':
        """Load configuration from environment variables."""
        # Explicitly load .env from script directory
        script_dir = Path(__file__).parent
        env_path = script_dir / '.env'
        load_dotenv(env_path)

        fqdn = os.getenv('CP_FQDN', '').strip()
        username = os.getenv('CP_USERNAME', '').strip()
        password = os.getenv('CP_PASSWORD', '').strip()
        api_key = os.getenv('CP_API_KEY', '').strip() or None
        verify_ssl = os.getenv('CP_VERIFY_SSL', 'true').lower() == 'true'
        dpsk_pool_id = os.getenv('CP_DPSK_POOL_ID', '').strip() or None

        if not fqdn:
            raise ValueError("CP_FQDN environment variable is required")
        if not username:
            raise ValueError("CP_USERNAME environment variable is required")
        if not password:
            raise ValueError("CP_PASSWORD environment variable is required")

        return cls(
            fqdn=fqdn,
            username=username,
            password=password,
            api_key=api_key,
            verify_ssl=verify_ssl,
            dpsk_pool_id=dpsk_pool_id
        )


@dataclass
class TokenInfo:
    """JWT token information."""
    token: str
    expires_at: datetime
    username: str

    @property
    def is_expired(self) -> bool:
        # Refresh 30 seconds before actual expiry for safety
        return datetime.now() >= (self.expires_at - timedelta(seconds=30))

    @property
    def time_remaining(self) -> timedelta:
        return self.expires_at - datetime.now()


class CloudpathAPIClient:
    """
    Client for interacting with Cloudpath REST API.

    Handles JWT authentication, automatic token refresh, pagination,
    and error handling.
    """

    def __init__(self, config: CloudpathConfig):
        self.config = config
        self.token_info: Optional[TokenInfo] = None
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Default headers
        session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

        return session

    def authenticate(self) -> TokenInfo:
        """
        Authenticate with Cloudpath and obtain JWT token.

        POST /admin/publicApi/token with username/password
        """
        url = f"{self.config.base_url}/token"

        payload = {
            "userName": self.config.username,
            "password": self.config.password
        }

        logger.info(f"Authenticating with Cloudpath at {self.config.fqdn}...")

        try:
            response = self.session.post(
                url,
                json=payload,
                verify=self.config.verify_ssl,
                timeout=self.config.timeout
            )
            response.raise_for_status()

            data = response.json()

            # Parse expiration datetime
            expire_str = data.get('expireDateTime', '')
            # Handle ISO8601 format with timezone: "2019-12-04T12:06:51-07:00[America/Denver]"
            # Remove the bracketed timezone name if present
            if '[' in expire_str:
                expire_str = expire_str.split('[')[0]

            try:
                expires_at = datetime.fromisoformat(expire_str)
                # Convert to local time if needed
                if expires_at.tzinfo:
                    expires_at = expires_at.replace(tzinfo=None)
            except ValueError:
                # Default to 5 minutes from now if parsing fails
                expires_at = datetime.now() + timedelta(minutes=5)
                logger.warning(f"Could not parse expiry time '{expire_str}', using 5 minute default")

            self.token_info = TokenInfo(
                token=data['token'],
                expires_at=expires_at,
                username=data.get('userName', self.config.username)
            )

            logger.info(f"Authentication successful. Token expires at {expires_at}")
            return self.token_info

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise AuthenticationError("Invalid credentials") from e
            raise
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to connect to Cloudpath: {e}") from e

    def refresh_token(self) -> TokenInfo:
        """
        Refresh the JWT token before it expires.

        PUT /admin/publicApi/token with current token in Authorization header
        """
        if not self.token_info:
            return self.authenticate()

        url = f"{self.config.base_url}/token"

        headers = {
            'Authorization': f'Bearer {self.token_info.token}'
        }

        logger.info("Refreshing authentication token...")

        try:
            response = self.session.put(
                url,
                headers=headers,
                verify=self.config.verify_ssl,
                timeout=self.config.timeout
            )
            response.raise_for_status()

            data = response.json()

            expire_str = data.get('expireDateTime', '')
            if '[' in expire_str:
                expire_str = expire_str.split('[')[0]

            try:
                expires_at = datetime.fromisoformat(expire_str)
                if expires_at.tzinfo:
                    expires_at = expires_at.replace(tzinfo=None)
            except ValueError:
                expires_at = datetime.now() + timedelta(minutes=5)

            self.token_info = TokenInfo(
                token=data['token'],
                expires_at=expires_at,
                username=data.get('userName', self.config.username)
            )

            logger.info(f"Token refreshed. New expiry: {expires_at}")
            return self.token_info

        except requests.exceptions.HTTPError as e:
            if e.response.status_code in (401, 406):
                # Token expired or invalid, re-authenticate
                logger.warning("Token refresh failed, re-authenticating...")
                return self.authenticate()
            raise

    def ensure_valid_token(self) -> str:
        """Ensure we have a valid token, refreshing if necessary."""
        if not self.token_info:
            self.authenticate()
        elif self.token_info.is_expired:
            self.refresh_token()

        return self.token_info.token

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        **kwargs
    ) -> requests.Response:
        """Make an authenticated API request."""
        token = self.ensure_valid_token()

        url = f"{self.config.base_url}/{endpoint.lstrip('/')}"

        headers = kwargs.pop('headers', {})
        # Cloudpath expects just the token value, not "Bearer {token}"
        headers['Authorization'] = token

        response = self.session.request(
            method=method,
            url=url,
            params=params,
            json=data,
            headers=headers,
            verify=self.config.verify_ssl,
            timeout=self.config.timeout,
            **kwargs
        )

        return response

    def get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        """Make a GET request to the API."""
        response = self._make_request('GET', endpoint, params=params)
        response.raise_for_status()
        return response.json()

    def get_all_pages(self, endpoint: str, params: Optional[dict] = None) -> list:
        """
        Retrieve all pages of a paginated endpoint.

        Returns a flat list of all items across all pages.
        """
        all_items = []
        page = 1
        params = params or {}
        params['pageSize'] = self.config.page_size

        while True:
            params['page'] = page

            try:
                response = self.get(endpoint, params)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    # Endpoint doesn't exist or no data
                    break
                raise

            # Handle paginated response format
            if isinstance(response, dict) and 'contents' in response:
                items = response.get('contents', [])
                page_info = response.get('page', {})
                total_count = page_info.get('totalCount', 0)

                all_items.extend(items)

                logger.debug(f"  Page {page}: {len(items)} items (total: {len(all_items)}/{total_count})")

                # Check if we've retrieved all items
                if len(all_items) >= total_count or len(items) < self.config.page_size:
                    break

                page += 1
            else:
                # Non-paginated response (single item or list)
                if isinstance(response, list):
                    all_items.extend(response)
                else:
                    all_items.append(response)
                break

        return all_items

    def get_server_info(self) -> dict:
        """Get basic server information from the token response."""
        if not self.token_info:
            self.authenticate()

        # Re-authenticate to get fresh server info
        url = f"{self.config.base_url}/token"

        response = self.session.post(
            url,
            json={
                "userName": self.config.username,
                "password": self.config.password
            },
            verify=self.config.verify_ssl,
            timeout=self.config.timeout
        )

        if response.ok:
            data = response.json()
            return {
                'serverVersion': data.get('serverVersion', 'unknown'),
                'fqdn': self.config.fqdn
            }

        return {'fqdn': self.config.fqdn}


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class CloudpathExtractor:
    """
    Main extraction orchestrator.

    Extracts Cloudpath configuration data from known working endpoints.
    """

    # Static list of confirmed working endpoints
    # Use cloudpath_discovery.py to probe for additional endpoints
    FUNCTIONAL_ENDPOINTS = [
        'authenticationServers',
        'radiusAttributeGroups',
        'enrollments',
        'certificateTemplates',
        'dpskPools',
        'policies',
    ]

    def __init__(self, client: CloudpathAPIClient):
        self.client = client
        self.data: dict[str, Any] = {}

    def _filter_dpsks(self, dpsks: list, pool_ssid_list: Optional[list] = None) -> list:
        """
        Filter DPSKs based on configured filters (ssid_match and/or name_match).

        Both filters must match if both are specified (AND logic).
        For SSID filtering, if a DPSK has an empty ssidList, it inherits from the pool.
        Returns the filtered list, or the original list if no filters are configured.
        """
        ssid_match = self.client.config.ssid_match
        name_match = self.client.config.name_match
        name_match_strip = self.client.config.name_match_strip

        # Use name_match_strip as filter if no name_match specified
        effective_name_match = name_match or name_match_strip

        if not ssid_match and not effective_name_match:
            return dpsks

        # Get pool's ssidList as fallback for DPSKs that inherit
        if pool_ssid_list is None and 'pool' in self.data:
            pool_ssid_list = self.data['pool'].get('ssidList', [])

        # Convert pool ssidList to string for matching
        pool_ssids_str = ''
        if pool_ssid_list:
            if isinstance(pool_ssid_list, list):
                pool_ssids_str = ','.join(pool_ssid_list)
            else:
                pool_ssids_str = str(pool_ssid_list)

        filtered = []
        for dpsk in dpsks:
            if not isinstance(dpsk, dict):
                continue

            # Check SSID filter
            if ssid_match:
                ssid_list = dpsk.get('ssidList', [])
                # ssidList can be a string (comma-separated) or possibly a list
                if isinstance(ssid_list, list):
                    ssid_list_str = ','.join(ssid_list) if ssid_list else ''
                else:
                    ssid_list_str = ssid_list or ''

                # If DPSK has no SSIDs, inherit from pool
                if not ssid_list_str and pool_ssids_str:
                    ssid_list_str = pool_ssids_str
                    logger.debug(f"  DPSK '{dpsk.get('name')}' inherits pool SSIDs: {pool_ssids_str[:50]}...")

                if ssid_match not in ssid_list_str:
                    continue

            # Check name filter
            if effective_name_match:
                dpsk_name = dpsk.get('name', '')
                if effective_name_match not in dpsk_name:
                    continue

            filtered.append(dpsk)

        # Log filter results
        filters_applied = []
        if ssid_match:
            filters_applied.append(f"ssid='{ssid_match}'")
        if effective_name_match:
            filters_applied.append(f"name='{effective_name_match}'")
        logger.info(f"DPSK filter [{', '.join(filters_applied)}]: {len(filtered)}/{len(dpsks)} matched")

        return filtered

    def _enrich_dpsk_details(self, dpsks: list, pool_id: str) -> list:
        """
        Fetch full details for each DPSK by hitting individual endpoints.

        This gets complete data including SSID overrides that may not be
        returned by the list endpoint.
        """
        logger.info(f"Fetching full details for {len(dpsks)} DPSKs...")
        enriched = []

        for i, dpsk in enumerate(dpsks):
            if not isinstance(dpsk, dict):
                enriched.append(dpsk)
                continue

            dpsk_id = dpsk.get('guid')
            dpsk_name = dpsk.get('name', dpsk_id)

            if not dpsk_id:
                enriched.append(dpsk)
                continue

            try:
                # Hit the individual DPSK endpoint to get full details
                full_dpsk = self.client.get(f"dpskPools/{pool_id}/dpsks/{dpsk_id}")
                enriched.append(full_dpsk)

                # Log progress every 50 DPSKs or for small sets
                if (i + 1) % 50 == 0 or len(dpsks) <= 10:
                    logger.info(f"  Enriched {i + 1}/{len(dpsks)} DPSKs")

            except requests.exceptions.HTTPError as e:
                logger.warning(f"  Could not get details for {dpsk_name}: {e}")
                enriched.append(dpsk)  # Keep original if fetch fails
            except Exception as e:
                logger.debug(f"  Error getting details for {dpsk_name}: {e}")
                enriched.append(dpsk)

        logger.info(f"Enrichment complete: {len(enriched)} DPSKs")
        return enriched

    def _strip_from_names(self, dpsks: list, strip_str: str) -> list:
        """
        Strip matched string from DPSK names and clean up double delimiters.

        Example: "chris13_avalon_foo_fast" with strip "avalon_foo" -> "chris13_fast"
        """
        import re

        for dpsk in dpsks:
            if not isinstance(dpsk, dict):
                continue

            name = dpsk.get('name', '')
            if not name or strip_str not in name:
                continue

            # Store original name
            dpsk['originalName'] = name

            # Remove the matched string
            new_name = name.replace(strip_str, '')

            # Clean up double/triple delimiters (_, -, .)
            new_name = re.sub(r'[_\-\.]{2,}', lambda m: m.group(0)[0], new_name)

            # Remove leading/trailing delimiters
            new_name = new_name.strip('_-.')

            dpsk['name'] = new_name
            logger.debug(f"  Stripped name: '{name}' -> '{new_name}'")

        return dpsks

    def _populate_inherited_ssids(self, dpsks: list, pool_ssid_list: Optional[list] = None) -> list:
        """
        Populate ssidList with inherited pool SSIDs for DPSKs that have empty lists.
        """
        # Get pool's ssidList if not provided
        if pool_ssid_list is None and 'pool' in self.data:
            pool_ssid_list = self.data['pool'].get('ssidList', [])

        for dpsk in dpsks:
            if not isinstance(dpsk, dict):
                continue

            # If DPSK has no SSIDs, inherit from pool
            if not dpsk.get('ssidList'):
                dpsk['ssidList'] = pool_ssid_list or []

        return dpsks

    def extract_dpsk_only(self, pool_id: str) -> dict:
        """
        Fast extraction: only get pool details and DPSKs from a single pool.

        Skips endpoint discovery and all other resources.
        Hits /dpskPools/{pool_id} for pool info, then /dpskPools/{pool_id}/dpsks
        """
        start_time = datetime.now()
        logger.info("=" * 60)
        logger.info(f"Fast DPSK Extraction - Pool: {pool_id}")
        logger.info("=" * 60)

        self.data = {
            'metadata': {
                'extracted_at': start_time.isoformat(),
                'cloudpath_fqdn': self.client.config.fqdn,
                'extractor_version': '1.0.0',
                'mode': 'dpsk_only',
                'pool_id': pool_id,
                'full_details': self.client.config.full_details
            }
        }

        # First fetch the pool details
        logger.info(f"Fetching pool details for {pool_id}...")
        try:
            pool = self.client.get(f"dpskPools/{pool_id}")
            self.data['pool'] = pool
            pool_name = pool.get('displayName') or pool.get('name') or pool_id
            logger.info(f"Retrieved pool: {pool_name}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.error(f"Pool not found: {pool_id}")
                self.data['pool'] = None
                self.data['dpsks'] = []
                self.data['error'] = f"Pool not found: {pool_id}"
                return self.data
            else:
                raise

        # Then fetch DPSKs from the pool
        logger.info(f"Fetching DPSKs from pool {pool_id}...")
        try:
            dpsks = self.client.get_all_pages(f"dpskPools/{pool_id}/dpsks")
            logger.info(f"Retrieved {len(dpsks)} DPSKs")

            # Optionally fetch full details for each DPSK
            if self.client.config.full_details:
                dpsks = self._enrich_dpsk_details(dpsks, pool_id)

            # Apply filters if configured
            dpsks = self._filter_dpsks(dpsks)

            # Strip matched string from names if requested
            if self.client.config.name_match_strip:
                dpsks = self._strip_from_names(dpsks, self.client.config.name_match_strip)

            # Populate inherited SSIDs
            dpsks = self._populate_inherited_ssids(dpsks)

            self.data['dpsks'] = dpsks
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"No DPSKs endpoint for pool: {pool_id}")
                self.data['dpsks'] = []
            else:
                raise

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.data['metadata']['extraction_duration_seconds'] = duration

        logger.info(f"Extraction complete in {duration:.1f} seconds")
        return self.data

    def extract_all(self) -> dict:
        """
        Extract all available configuration from Cloudpath.

        Returns a comprehensive nested dictionary of all data.
        """
        start_time = datetime.now()
        logger.info("=" * 60)
        logger.info("Starting Cloudpath Full Configuration Extraction")
        logger.info("=" * 60)

        # Initialize metadata
        self.data = {
            'metadata': {
                'extracted_at': start_time.isoformat(),
                'cloudpath_fqdn': self.client.config.fqdn,
                'extractor_version': '1.0.0'
            }
        }

        # Get server info
        try:
            server_info = self.client.get_server_info()
            self.data['metadata'].update(server_info)
        except Exception as e:
            logger.warning(f"Could not retrieve server info: {e}")

        # Extract data from known functional endpoints
        logger.info(f"Extracting from {len(self.FUNCTIONAL_ENDPOINTS)} endpoints...")

        for endpoint in self.FUNCTIONAL_ENDPOINTS:
            self._extract_endpoint(endpoint)

        # Extract nested/related resources
        self._extract_nested_resources()

        # Calculate extraction stats
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        self.data['metadata']['extraction_duration_seconds'] = duration
        self.data['metadata']['endpoints_extracted'] = len(self.FUNCTIONAL_ENDPOINTS)

        logger.info("=" * 60)
        logger.info(f"Extraction complete in {duration:.1f} seconds")
        logger.info(f"Extracted {len(self.FUNCTIONAL_ENDPOINTS)} endpoint categories")
        logger.info("=" * 60)

        return self.data

    def _extract_endpoint(self, endpoint: str):
        """Extract all data from a single endpoint."""
        # Convert endpoint name to Python-friendly key
        key = endpoint.replace('-', '_')

        logger.info(f"Extracting: {endpoint}...")

        try:
            items = self.client.get_all_pages(endpoint)
            self.data[key] = items
            logger.info(f"  Retrieved {len(items)} {endpoint}")
        except Exception as e:
            logger.error(f"  Failed to extract {endpoint}: {e}")
            self.data[key] = {'error': str(e)}

    def _extract_nested_resources(self):
        """Extract nested resources using HATEOAS links from API responses."""

        logger.info("Extracting nested resources via HATEOAS links...")

        # Process all top-level resources that have items with links
        for key, items in list(self.data.items()):
            if key == 'metadata' or not isinstance(items, list):
                continue

            for item in items:
                if not isinstance(item, dict):
                    continue

                self._follow_item_links(item, key)

        # Also try known nested patterns for camelCase endpoints
        if 'authenticationServers' in self.data:
            self._extract_auth_server_users()

        if 'dpskPools' in self.data:
            self._extract_dpsk_pool_items()

    def _follow_item_links(self, item: dict, parent_key: str):
        """
        Follow HATEOAS links in an item to extract nested resources.

        The API returns links like:
        {"rel": "certificates", "href": "https://.../certificateTemplates/1/certificates?..."}
        """
        links = item.get('links', [])
        if not links:
            return

        item_name = item.get('name') or item.get('guid') or 'unknown'

        for link in links:
            if not isinstance(link, dict):
                continue

            rel = link.get('rel', '')
            href = link.get('href', '')

            # Skip self-referential links
            if rel == 'self' or not href:
                continue

            # Extract the endpoint path from the URL
            # href can be:
            #   - Full URL: https://cp.rossho.me/admin/publicApi/certificateTemplates/1/certificates?page=1&pageSize=10
            #   - Relative with publicApi: publicApi/authenticationServers/1/users
            #   - Relative with leading slash: /publicApi/authenticationServers/2/users
            try:
                endpoint = None

                if '/admin/publicApi/' in href:
                    # Full URL format
                    endpoint = href.split('/admin/publicApi/')[1]
                elif href.startswith('publicApi/'):
                    # Relative without leading slash
                    endpoint = href[len('publicApi/'):]
                elif href.startswith('/publicApi/'):
                    # Relative with leading slash
                    endpoint = href[len('/publicApi/'):]

                if endpoint:
                    # Remove query parameters
                    endpoint = endpoint.split('?')[0]
                    # Remove template parameters like {&filter,orderBy}
                    endpoint = endpoint.split('{')[0]
                    # Clean up any trailing slashes
                    endpoint = endpoint.rstrip('/')

                    logger.info(f"  Following link '{rel}' for {parent_key}/{item_name}...")

                    try:
                        nested_items = self.client.get_all_pages(endpoint)
                        item[rel] = nested_items
                        logger.info(f"    Retrieved {len(nested_items)} {rel}")
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code not in (404, 403):
                            logger.warning(f"    Could not get {rel}: {e}")
                        item[rel] = []
                    except Exception as e:
                        logger.debug(f"    Error getting {rel}: {e}")
                        item[rel] = []

            except Exception as e:
                logger.debug(f"  Could not parse link {href}: {e}")

    def _extract_auth_server_users(self):
        """Extract users and groups from each authentication server."""
        auth_servers = self.data.get('authenticationServers', [])

        if not isinstance(auth_servers, list) or len(auth_servers) == 0:
            return

        logger.info("Extracting data from authentication servers...")

        for server in auth_servers:
            if not isinstance(server, dict):
                continue

            server_id = server.get('guid') or server.get('id')
            server_name = server.get('name', server_id)

            if not server_id:
                continue

            # Extract groups for this auth server
            if 'groups' not in server:
                try:
                    groups = self.client.get_all_pages(
                        f"authenticationServers/{server_id}/groups"
                    )
                    server['groups'] = groups
                    logger.info(f"  {server_name}: {len(groups)} groups")
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code != 404:
                        logger.warning(f"  Could not get groups for {server_name}: {e}")
                    server['groups'] = []
                except Exception as e:
                    logger.warning(f"  Error getting groups for {server_name}: {e}")
                    server['groups'] = []

            # Extract users for this auth server
            if 'users' not in server:
                try:
                    users = self.client.get_all_pages(
                        f"authenticationServers/{server_id}/users"
                    )
                    server['users'] = users
                    logger.info(f"  {server_name}: {len(users)} users")

                    # For each user, extract their groups
                    for user in users:
                        user_id = user.get('guid') or user.get('id')
                        if user_id and 'groups' not in user:
                            try:
                                user_groups = self.client.get_all_pages(
                                    f"authenticationServers/{server_id}/users/{user_id}/groups"
                                )
                                user['groups'] = user_groups
                            except:
                                user['groups'] = []

                except requests.exceptions.HTTPError as e:
                    if e.response.status_code != 404:
                        logger.warning(f"  Could not get users for {server_name}: {e}")
                    server['users'] = []
                except Exception as e:
                    logger.warning(f"  Error getting users for {server_name}: {e}")
                    server['users'] = []

    def _extract_dpsk_pool_items(self):
        """Extract DPSKs and their devices from DPSK pool(s).

        If a specific pool ID is configured, only extract from that pool.
        Otherwise, extract from all pools.
        """
        pools = self.data.get('dpskPools', [])

        if not isinstance(pools, list) or len(pools) == 0:
            return

        # Filter to specific pool if configured
        target_pool_id = self.client.config.dpsk_pool_id
        if target_pool_id:
            pools = [p for p in pools if isinstance(p, dict) and
                     (p.get('guid') == target_pool_id or
                      p.get('id') == target_pool_id or
                      str(p.get('guid')) == target_pool_id or
                      str(p.get('id')) == target_pool_id)]
            if not pools:
                logger.warning(f"No pool found matching ID: {target_pool_id}")
                return
            logger.info(f"Extracting DPSKs from specific pool: {target_pool_id}")
        else:
            logger.info("Extracting DPSKs from all DPSK pools...")

        for pool in pools:
            if not isinstance(pool, dict):
                continue

            pool_id = pool.get('guid') or pool.get('id')
            pool_name = pool.get('displayName') or pool.get('name') or pool_id

            if not pool_id:
                continue

            # Get pool's ssidList for inheritance fallback
            pool_ssid_list = pool.get('ssidList', [])

            # Skip if already extracted via HATEOAS links
            if 'dpsks' in pool:
                dpsks = pool['dpsks']
                # Apply SSID filter if configured (with pool ssidList fallback)
                dpsks = self._filter_dpsks(dpsks, pool_ssid_list)
                # Strip matched string from names if requested
                if self.client.config.name_match_strip:
                    dpsks = self._strip_from_names(dpsks, self.client.config.name_match_strip)
                # Populate inherited SSIDs
                dpsks = self._populate_inherited_ssids(dpsks, pool_ssid_list)
                pool['dpsks'] = dpsks
            else:
                try:
                    dpsks = self.client.get_all_pages(f"dpskPools/{pool_id}/dpsks")
                    logger.info(f"  {pool_name}: {len(dpsks)} DPSKs")
                    # Apply SSID filter if configured (with pool ssidList fallback)
                    dpsks = self._filter_dpsks(dpsks, pool_ssid_list)
                    # Strip matched string from names if requested
                    if self.client.config.name_match_strip:
                        dpsks = self._strip_from_names(dpsks, self.client.config.name_match_strip)
                    # Populate inherited SSIDs
                    dpsks = self._populate_inherited_ssids(dpsks, pool_ssid_list)
                    pool['dpsks'] = dpsks
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code != 404:
                        logger.warning(f"  Could not get DPSKs for {pool_name}: {e}")
                    pool['dpsks'] = []
                    dpsks = []
                except Exception as e:
                    logger.warning(f"  Error getting DPSKs for {pool_name}: {e}")
                    pool['dpsks'] = []
                    dpsks = []

            # Extract devices for each DPSK
            for dpsk in dpsks:
                if not isinstance(dpsk, dict):
                    continue

                dpsk_id = dpsk.get('guid') or dpsk.get('id')
                dpsk_name = dpsk.get('name') or dpsk_id

                if not dpsk_id or 'devices' in dpsk:
                    continue

                # Only fetch devices if deviceCount > 0
                device_count = dpsk.get('deviceCount', 0)
                if device_count > 0:
                    try:
                        devices = self.client.get_all_pages(
                            f"dpskPools/{pool_id}/dpsks/{dpsk_id}/devices"
                        )
                        dpsk['devices'] = devices
                        logger.info(f"    {dpsk_name}: {len(devices)} devices")
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code != 404:
                            logger.debug(f"    Could not get devices for {dpsk_name}: {e}")
                        dpsk['devices'] = []
                    except Exception as e:
                        logger.debug(f"    Error getting devices for {dpsk_name}: {e}")
                        dpsk['devices'] = []
                else:
                    dpsk['devices'] = []

    def _enrich_enrollments(self):
        """Enrich enrollment records with additional details if available."""
        enrollments = self.data.get('enrollments', [])

        if not isinstance(enrollments, list) or len(enrollments) == 0:
            return

        # For large enrollment sets, we may want to limit enrichment
        # or skip it entirely to avoid API overload
        if len(enrollments) > 1000:
            logger.info(f"Skipping enrollment enrichment ({len(enrollments)} records)")
            return

        logger.info("Enriching enrollment records...")

        enriched = 0
        for enrollment in enrollments[:100]:  # Limit to first 100 for safety
            if not isinstance(enrollment, dict):
                continue

            enrollment_id = enrollment.get('guid') or enrollment.get('id')
            if not enrollment_id:
                continue

            try:
                # Try to get additional enrollment details
                details = self.client.get(f"enrollments/{enrollment_id}")
                enrollment.update(details)
                enriched += 1
            except:
                pass  # Skip if details unavailable

        if enriched > 0:
            logger.info(f"  Enriched {enriched} enrollment records")

    def save_to_file(self, output_dir: str = './output', max_files: int = 5) -> Path:
        """
        Save extracted data to a JSON file.

        Maintains only the last N output files, deleting older ones.
        Returns the path to the saved file.
        """
        # Create output directory if needed
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Clean up old JSON files, keeping only the most recent (max_files - 1)
        fqdn_safe = self.client.config.fqdn.replace('.', '_').replace(':', '_')
        pattern = f"cloudpath_{fqdn_safe}_*.json"
        existing_files = sorted(output_path.glob(pattern), key=os.path.getmtime)

        while len(existing_files) >= max_files:
            oldest = existing_files.pop(0)
            try:
                oldest.unlink()
                logger.debug(f"Deleted old output file: {oldest.name}")
            except OSError:
                pass

        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"cloudpath_{fqdn_safe}_{timestamp}.json"

        filepath = output_path / filename

        # Write JSON with nice formatting
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, default=str, ensure_ascii=False)

        file_size = filepath.stat().st_size
        logger.info(f"Saved extraction to: {filepath}")
        logger.info(f"File size: {file_size / 1024 / 1024:.2f} MB")

        return filepath


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Extract DPSK configuration from Cloudpath deployment via REST API.\n'
                    'Run without arguments to list available DPSK pools.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available DPSK pools (default behavior)
  python cloudpath_extractor.py

  # Extract DPSKs from a specific pool
  python cloudpath_extractor.py --pool-id <GUID>

  # Filter DPSKs to only those with a specific SSID
  python cloudpath_extractor.py --pool-id <GUID> --ssid-match "@sitename_foo"

  # Filter DPSKs by name
  python cloudpath_extractor.py --pool-id <GUID> --name-match "SiteName"

  # Combine filters (both must match)
  python cloudpath_extractor.py --pool-id <GUID> --ssid-match "@sitename_x" --name-match "Unit"

  # Fetch full details including per-DPSK SSID overrides (slower)
  python cloudpath_extractor.py --pool-id <GUID> --full-details

  # Extract ALL pools (use with caution!)
  python cloudpath_extractor.py --all-pools-yes-really
        """
    )
    parser.add_argument(
        '--pool-id', '-p',
        dest='dpsk_pool_id',
        help='DPSK pool GUID to extract from (required for extraction)'
    )
    parser.add_argument(
        '--all-pools-yes-really',
        action='store_true',
        dest='extract_all_pools',
        help='Extract ALL DPSK pools (use with caution on large deployments)'
    )
    parser.add_argument(
        '--output-dir', '-o',
        dest='output_dir',
        help='Output directory for JSON files (default: ./output)'
    )
    parser.add_argument(
        '--ssid-match',
        dest='ssid_match',
        help='Filter DPSKs to only those with this string in their ssidList (e.g., "sitename_foo")'
    )
    parser.add_argument(
        '--name-match',
        dest='name_match',
        help='Filter DPSKs to only those with this string in their name (e.g., "SiteName")'
    )
    parser.add_argument(
        '--name-match-and-strip',
        dest='name_match_strip',
        help='Filter by name AND strip the matched string from output (cleans up double delimiters)'
    )
    parser.add_argument(
        '--full-details',
        action='store_true',
        dest='full_details',
        help='Fetch full details for each DPSK (slower, but gets SSID overrides)'
    )
    return parser.parse_args()


def list_dpsk_pools(client: CloudpathAPIClient) -> int:
    """
    Fetch and display available DPSK pools, then exit.

    Returns exit code (0 for success).
    """
    print("Fetching available DPSK pools...\n")

    try:
        pools = client.get_all_pages('dpskPools')
    except Exception as e:
        logger.error(f"Failed to fetch DPSK pools: {e}")
        print(f"Error fetching pools: {e}")
        return 1

    if not pools:
        print("No DPSK pools found on this server.")
        return 0

    print(f"Found {len(pools)} DPSK pool(s):\n")
    print("-" * 80)

    for pool in pools:
        guid = pool.get('guid', 'N/A')
        name = pool.get('displayName') or pool.get('name') or '(unnamed)'
        description = pool.get('description', '')
        enabled = pool.get('enabled', False)
        ssid_list = pool.get('ssidList', [])
        if isinstance(ssid_list, list):
            ssids = ', '.join(ssid_list) if ssid_list else '(none)'
        else:
            ssids = ssid_list or '(none)'

        status = "enabled" if enabled else "disabled"

        print(f"  Name: {name}")
        print(f"  GUID: {guid}")
        if description:
            print(f"  Description: {description}")
        print(f"  Status: {status}")
        print(f"  SSIDs: {ssids}")
        print("-" * 80)

    print("\nTo extract DPSKs from a specific pool, re-run with:")
    print(f"  python cloudpath_extractor.py --pool-id <GUID>")
    print("\nExample:")
    print(f"  python cloudpath_extractor.py --pool-id \"{pools[0].get('guid')}\"")

    return 0


def main():
    """Main entry point."""
    args = parse_args()

    print("\n" + "=" * 60)
    print("  Cloudpath Configuration Extractor")
    print("=" * 60 + "\n")

    try:
        # Load configuration from environment
        config = CloudpathConfig.from_env()

        # Command-line pool ID overrides environment variable
        if args.dpsk_pool_id:
            config.dpsk_pool_id = args.dpsk_pool_id

        # Set SSID match filter from command-line
        if args.ssid_match:
            config.ssid_match = args.ssid_match

        # Set name match filter from command-line
        if args.name_match:
            config.name_match = args.name_match

        # Set name match and strip from command-line
        if args.name_match_strip:
            config.name_match_strip = args.name_match_strip

        # Set full details mode from command-line
        if args.full_details:
            config.full_details = True

        logger.info(f"Target: {config.fqdn}")

        if config.dpsk_pool_id:
            logger.info(f"DPSK Pool Filter: {config.dpsk_pool_id}")
        if config.ssid_match:
            logger.info(f"SSID Match Filter: {config.ssid_match}")
        if config.name_match:
            logger.info(f"Name Match Filter: {config.name_match}")
        if config.name_match_strip:
            logger.info(f"Name Match & Strip: {config.name_match_strip}")
        if config.full_details:
            logger.info("Full Details Mode: enabled (will fetch each DPSK individually)")

        # Create API client
        client = CloudpathAPIClient(config)

        # Authenticate
        client.authenticate()

        # If no pool ID specified, list available pools and exit (unless --all-pools-yes-really)
        if not config.dpsk_pool_id and not args.extract_all_pools:
            return list_dpsk_pools(client)

        # Create extractor and run
        extractor = CloudpathExtractor(client)

        if args.extract_all_pools:
            # Full extraction of ALL pools
            logger.warning("Extracting ALL DPSK pools - this may take a while on large deployments")
            data = extractor.extract_all()
        else:
            # Extract from specific pool only
            data = extractor.extract_dpsk_only(config.dpsk_pool_id)

        # Save results
        output_dir = args.output_dir or os.getenv('OUTPUT_DIR', './output')
        output_file = extractor.save_to_file(output_dir)

        print(f"\nExtraction complete!")
        print(f"Output saved to: {output_file}")

        # Print summary
        print("\nExtracted resources:")
        for key, value in data.items():
            if key == 'metadata':
                continue
            if isinstance(value, list):
                print(f"  - {key}: {len(value)} items")
            elif isinstance(value, dict) and 'error' in value:
                print(f"  - {key}: ERROR - {value['error']}")

        return 0

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        print(f"\nError: {e}")
        print("\nPlease ensure your .env file contains:")
        print("  CP_FQDN=your-cloudpath-server.com")
        print("  CP_USERNAME=admin@example.com")
        print("  CP_PASSWORD=your-password")
        return 1

    except AuthenticationError as e:
        logger.error(f"Authentication failed: {e}")
        print(f"\nAuthentication failed: {e}")
        print("Please check your username and password.")
        return 1

    except ConnectionError as e:
        logger.error(f"Connection failed: {e}")
        print(f"\nConnection failed: {e}")
        print("Please check the FQDN and network connectivity.")
        return 1

    except KeyboardInterrupt:
        print("\n\nExtraction cancelled by user.")
        return 130

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"\nUnexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())

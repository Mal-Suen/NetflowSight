"""
Threat Intelligence Client for AbuseIPDB and other services
"""

import logging
from typing import Optional

import requests

from core.config import settings
from core.models import IPReputation

logger = logging.getLogger(__name__)


class ThreatIntelligenceClient:
    """
    Client for threat intelligence APIs.

    Supports:
    - AbuseIPDB
    - VirusTotal (future)
    """

    def __init__(self):
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
        })

    def check_abuseipdb(self, ip: str, max_age_days: int = 90) -> Optional[IPReputation]:
        """
        Check IP against AbuseIPDB.

        Args:
            ip: IP address to check
            max_age_days: Maximum age of reports to consider

        Returns:
            IPReputation object or None if check fails
        """
        if not self.abuseipdb_key:
            logger.warning("AbuseIPDB API key not configured")
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.abuseipdb_key,
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": "",
        }

        try:
            response = self.session.get(url, headers=headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json().get("data", {})
                return IPReputation(
                    ip=ip,
                    abuse_score=data.get("abuseConfidenceScore", 0),
                    country_code=data.get("countryCode"),
                    usage_type=data.get("usageType"),
                    isp=data.get("isp"),
                    domain=data.get("domain"),
                    is_tor=data.get("isTor", False),
                    is_public=data.get("isPublic", True),
                    reports_count=data.get("totalReports", 0),
                )
            elif response.status_code == 401:
                logger.error("AbuseIPDB API key is invalid or expired")
            elif response.status_code == 429:
                logger.warning("AbuseIPDB rate limit exceeded")
            else:
                error_detail = response.content[:200].decode("utf-8", errors="replace")
                logger.warning(
                    f"AbuseIPDB request failed: {response.status_code} - {error_detail}"
                )
        except requests.RequestException as e:
            logger.error(f"Error querying AbuseIPDB: {e}")

        return None

    def check_multiple_ips(self, ips: list[str]) -> dict[str, Optional[IPReputation]]:
        """
        Check multiple IPs and return results.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary mapping IP to IPReputation
        """
        results = {}
        for ip in ips:
            results[ip] = self.check_abuseipdb(ip)
        return results

    def close(self):
        """Close the HTTP session and release resources."""
        if self.session:
            self.session.close()
            logger.debug("Threat intelligence client session closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False

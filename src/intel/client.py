"""威胁情报 API 客户端模块"""

import logging
from typing import Optional
import requests

from core.config import settings
from core.models import IPReputation

logger = logging.getLogger(__name__)


class ThreatIntelligenceClient:
    """威胁情报 API 客户端，支持 AbuseIPDB"""

    def __init__(self):
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def check_abuseipdb(self, ip: str, max_age_days: int = 90) -> Optional[IPReputation]:
        """查询 AbuseIPDB 获取 IP 信誉信息"""
        if not self.abuseipdb_key:
            logger.warning("AbuseIPDB API 密钥未配置")
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key}
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""}

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
                logger.error("AbuseIPDB API 密钥无效")
            elif response.status_code == 429:
                logger.warning("AbuseIPDB API 请求频率超限")
            else:
                logger.warning(f"AbuseIPDB 请求失败: {response.status_code}")
        except requests.RequestException as e:
            logger.error(f"AbuseIPDB 查询异常: {e}")

        return None

    def check_multiple_ips(self, ips: list[str]) -> dict[str, Optional[IPReputation]]:
        """批量查询多个 IP"""
        return {ip: self.check_abuseipdb(ip) for ip in ips}

    def close(self):
        """关闭 HTTP 会话"""
        if self.session:
            self.session.close()

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close(); return False

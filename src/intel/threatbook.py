"""微步在线 ThreatBook API 客户端模块"""

import contextlib
import logging
from typing import Optional

import requests

from core.config import settings

logger = logging.getLogger(__name__)


class ThreatBookClient:
    """微步在线 ThreatBook API 客户端 (v3)"""

    def __init__(self):
        self.api_key = settings.THREATBOOK_API_KEY
        self.base_url = "https://api.threatbook.cn/v3/scene"
        self.session = requests.Session()

        if not self.api_key:
            logger.warning("ThreatBook API Key 未配置")

    def check_domain(self, domain: str) -> Optional[dict]:
        """查询域名威胁情报（DNS 失陷检测）"""
        if not self.api_key:
            return None

        url = f"{self.base_url}/dns"
        params = {"apikey": self.api_key, "resource": domain}

        try:
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("response_code") == 0:
                    return self._parse_domain_result(domain, data.get("data", {}))
            elif response.status_code == 401:
                logger.error("ThreatBook API Key 无效")
            elif response.status_code == 429:
                logger.warning("ThreatBook API 请求频率超限")
        except requests.RequestException as e:
            logger.error(f"ThreatBook 查询异常: {e}")

        return None

    def check_ip(self, ip: str) -> Optional[dict]:
        """查询 IP 威胁情报"""
        if not self.api_key:
            return None

        url = f"{self.base_url}/ip_reputation"
        params = {"apikey": self.api_key, "resource": ip}

        try:
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("response_code") == 0:
                    return self._parse_ip_result(ip, data.get("data", {}))
        except requests.RequestException as e:
            logger.error(f"ThreatBook 查询异常: {e}")

        return None

    def _parse_domain_result(self, domain: str, data: dict) -> dict:
        """解析域名查询结果"""
        domain_data = data.get("domains", {}).get(domain, {})
        if not domain_data:
            return {}
        return {
            "domain": domain,
            "severity": domain_data.get("severity", "unknown"),
            "judgments": domain_data.get("judgments", []),
            "is_malicious": domain_data.get("is_malicious", False),
            "is_suspicious": domain_data.get("severity") in ["suspicious", "malicious"],
            "confidence_level": domain_data.get("confidence_level", "unknown"),
        }

    def _parse_ip_result(self, ip: str, data: dict) -> dict:
        """解析 IP 查询结果"""
        ip_data = data.get(ip, {})
        if not ip_data:
            return {}
        return {
            "ip": ip,
            "severity": ip_data.get("severity", "unknown"),
            "judgments": ip_data.get("judgments", []),
            "is_malicious": ip_data.get("is_malicious", False),
            "is_suspicious": ip_data.get("severity") in ["suspicious", "malicious"],
            "scene": ip_data.get("scene", ""),
            "basic": ip_data.get("basic", {}),
        }

    def close(self):
        if self.session:
            self.session.close()

    def __del__(self):
        with contextlib.suppress(Exception):
            self.close()

"""
微步在线 ThreatBook API 客户端
用于查询 IP、域名、URL 的威胁情报
"""

import logging
from typing import Optional

import requests

from core.config import settings

logger = logging.getLogger(__name__)


class ThreatBookClient:
    """
    微步在线 ThreatBook API 客户端 (v3)
    
    免费额度：1000 次/天
    API 文档：https://x.threatbook.com/v5/apiDocs
    """

    def __init__(self):
        self.api_key = settings.THREATBOOK_API_KEY
        # 使用 v3 场景化 API
        self.base_url = "https://api.threatbook.cn/v3/scene"
        self.session = requests.Session()
        
        if not self.api_key:
            logger.warning("ThreatBook API Key 未配置，请在 .env 中设置 THREATBOOK_API_KEY")

    def check_domain(self, domain: str) -> Optional[dict]:
        """
        查询域名威胁情报（DNS 失陷检测）
        
        Args:
            domain: 域名
            
        Returns:
            威胁情报字典，或 None（如果查询失败）
        """
        if not self.api_key:
            return None
            
        url = f"{self.base_url}/dns"
        params = {
            "apikey": self.api_key,
            "resource": domain,
        }
        
        try:
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # 微步 v3 返回格式：{"response_code": 0, "data": {...}, "verbose_msg": "..."}
                if data.get("response_code") == 0:
                    return self._parse_domain_result(domain, data.get("data", {}))
                else:
                    logger.debug(f"ThreatBook 查询失败 ({data.get('response_code')}): {data.get('verbose_msg', 'Unknown error')}")
            elif response.status_code == 401:
                logger.error("ThreatBook API Key 无效或已过期")
            elif response.status_code == 429:
                logger.warning("ThreatBook API 请求频率超限")
            else:
                logger.warning(f"ThreatBook 请求失败: {response.status_code}")
        except requests.RequestException as e:
            logger.error(f"ThreatBook 查询异常: {e}")
            
        return None

    def check_ip(self, ip: str) -> Optional[dict]:
        """
        查询 IP 威胁情报（IP 信誉查询）
        
        Args:
            ip: IP 地址
            
        Returns:
            威胁情报字典，或 None（如果查询失败）
        """
        if not self.api_key:
            return None
            
        url = f"{self.base_url}/ip_reputation"
        params = {
            "apikey": self.api_key,
            "resource": ip,
        }
        
        try:
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("response_code") == 0:
                    return self._parse_ip_result(ip, data.get("data", {}))
                else:
                    logger.debug(f"ThreatBook 查询失败 ({data.get('response_code')}): {data.get('verbose_msg', 'Unknown error')}")
            elif response.status_code == 401:
                logger.error("ThreatBook API Key 无效或已过期")
            elif response.status_code == 429:
                logger.warning("ThreatBook API 请求频率超限")
            else:
                logger.warning(f"ThreatBook 请求失败: {response.status_code}")
        except requests.RequestException as e:
            logger.error(f"ThreatBook 查询异常: {e}")
            
        return None

    def _parse_domain_result(self, domain: str, data: dict) -> dict:
        """解析域名查询结果（v3 DNS 失陷检测）"""
        if not data:
            return {}
            
        # v3 DNS API 返回格式：{"domains": {"example.com": {...}}}
        domain_data = data.get("domains", {}).get(domain, {})
        if not domain_data:
            return {}
            
        return {
            "domain": domain,
            "severity": domain_data.get("severity", "unknown"),
            "judgments": domain_data.get("judgments", []),
            "tags_classes": domain_data.get("tags_classes", []),
            "is_malicious": domain_data.get("is_malicious", False),
            "is_suspicious": domain_data.get("severity") in ["suspicious", "malicious"],
            "confidence_level": domain_data.get("confidence_level", "unknown"),
            "categories": domain_data.get("categories", {}),
            "rank": domain_data.get("rank", {}),
            "permalink": domain_data.get("permalink", ""),
        }

    def _parse_ip_result(self, ip: str, data: dict) -> dict:
        """解析 IP 查询结果（v3 IP 信誉查询）"""
        if not data:
            return {}
            
        # v3 IP API 返回格式：{"8.8.8.8": {...}}
        ip_data = data.get(ip, {})
        if not ip_data:
            return {}
            
        return {
            "ip": ip,
            "severity": ip_data.get("severity", "unknown"),
            "judgments": ip_data.get("judgments", []),
            "tags_classes": ip_data.get("tags_classes", []),
            "is_malicious": ip_data.get("is_malicious", False),
            "is_suspicious": ip_data.get("severity") in ["suspicious", "malicious"],
            "confidence_level": ip_data.get("confidence_level", "unknown"),
            "scene": ip_data.get("scene", ""),
            "basic": ip_data.get("basic", {}),
            "asn": ip_data.get("asn", {}),
            "permalink": ip_data.get("permalink", ""),
        }

    def close(self):
        """关闭 HTTP 会话"""
        if self.session:
            self.session.close()

    def __del__(self):
        """析构函数"""
        try:
            self.close()
        except Exception:
            pass

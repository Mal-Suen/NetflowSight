"""配置管理模块 - 加载和管理全局配置"""

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


class Settings:
    """全局配置类，所有配置项通过环境变量读取"""

    # 威胁情报 API 配置
    ABUSEIPDB_API_KEY: Optional[str] = os.environ.get("ABUSEIPDB_API_KEY")
    VIRUSTOTAL_API_KEY: Optional[str] = os.environ.get("VIRUSTOTAL_API_KEY")
    THREATBOOK_API_KEY: Optional[str] = os.environ.get("THREATBOOK_API_KEY")

    # AI 配置
    OPENAI_API_KEY: Optional[str] = os.environ.get("OPENAI_API_KEY")
    AI_MODEL: str = os.environ.get("AI_MODEL", "gpt-4o-mini")
    AI_MAX_TOKENS: int = int(os.environ.get("AI_MAX_TOKENS", "4000"))

    # 分析设置
    SAFE_DOMAINS_FILE: str = os.environ.get("SAFE_DOMAINS_FILE", "data/safe_domains.txt")
    THREAT_CACHE_ENABLED: bool = os.environ.get("THREAT_CACHE_ENABLED", "true").lower() == "true"
    THREAT_CACHE_TTL_HOURS: int = int(os.environ.get("THREAT_CACHE_TTL_HOURS", "24"))

    # NFStream 性能参数
    NFSTREAM_N_METERS: int = int(os.environ.get("NFSTREAM_N_METERS", "0"))
    STATISTICAL_ANALYSIS: bool = os.environ.get("STATISTICAL_ANALYSIS", "true").lower() == "true"
    N_DISSECTIONS: int = int(os.environ.get("N_DISSECTIONS", "20"))
    DECODE_TUNNELS: bool = os.environ.get("DECODE_TUNNELS", "true").lower() == "true"

    # 日志配置
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.environ.get("LOG_FILE", "logs/netflowsight.log")

    # 内置安全域名白名单
    DEFAULT_SAFE_DOMAINS: set = frozenset({
        "google.com", "www.google.com", "googleapis.com",
        "microsoft.com", "windows.com", "msftconnecttest.com",
        "apple.com", "icloud.com", "mzstatic.com",
        "amazon.com", "amazonaws.com", "cloudfront.net",
        "facebook.com", "fbcdn.net", "twitter.com", "twimg.com",
        "cloudflare.com", "cdnjs.cloudflare.com",
        "github.com", "githubusercontent.com",
        "linkedin.com", "licdn.com",
        "akamai.net", "akamaiedge.net", "fastly.net",
    })

    @classmethod
    def load_safe_domains(cls) -> set[str]:
        """加载安全域名白名单，优先从文件加载，否则使用默认列表"""
        safe_domains = set(cls.DEFAULT_SAFE_DOMAINS)
        domains_file = Path(cls.SAFE_DOMAINS_FILE)
        if domains_file.exists():
            try:
                with open(domains_file, "r") as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith("#"):
                            safe_domains.add(domain.lower())
            except Exception as e:
                print(f"Warning: Failed to load safe domains file: {e}")
        return safe_domains

    @classmethod
    def is_configured(cls) -> dict[str, bool]:
        """检查各外部服务的配置状态"""
        return {
            "abuseipdb": bool(cls.ABUSEIPDB_API_KEY),
            "virustotal": bool(cls.VIRUSTOTAL_API_KEY),
            "threatbook": bool(cls.THREATBOOK_API_KEY),
            "openai": bool(cls.OPENAI_API_KEY),
        }


settings = Settings()

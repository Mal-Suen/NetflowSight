"""
Configuration management for NetflowSight
"""

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load .env file
load_dotenv()


class Settings:
    """Global settings for NetflowSight."""

    # Threat Intelligence APIs
    ABUSEIPDB_API_KEY: Optional[str] = os.environ.get("ABUSEIPDB_API_KEY")
    VIRUSTOTAL_API_KEY: Optional[str] = os.environ.get("VIRUSTOTAL_API_KEY")
    THREATBOOK_API_KEY: Optional[str] = os.environ.get("THREATBOOK_API_KEY")
    
    # AI Configuration
    OPENAI_API_KEY: Optional[str] = os.environ.get("OPENAI_API_KEY")
    AI_MODEL: str = os.environ.get("AI_MODEL", "gpt-4o-mini")
    AI_MAX_TOKENS: int = int(os.environ.get("AI_MAX_TOKENS", "4000"))
    
    # Analysis Settings
    SAFE_DOMAINS_FILE: str = os.environ.get(
        "SAFE_DOMAINS_FILE", "data/safe_domains.txt"
    )
    THREAT_CACHE_ENABLED: bool = os.environ.get(
        "THREAT_CACHE_ENABLED", "true"
    ).lower() == "true"
    THREAT_CACHE_TTL_HOURS: int = int(
        os.environ.get("THREAT_CACHE_TTL_HOURS", "24")
    )
    
    # Performance
    NFSTREAM_N_METERS: int = int(os.environ.get("NFSTREAM_N_METERS", "0"))
    STATISTICAL_ANALYSIS: bool = os.environ.get(
        "STATISTICAL_ANALYSIS", "true"
    ).lower() == "true"
    N_DISSECTIONS: int = int(os.environ.get("N_DISSECTIONS", "20"))
    DECODE_TUNNELS: bool = os.environ.get("DECODE_TUNNELS", "true").lower() == "true"
    
    # Logging
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.environ.get("LOG_FILE", "logs/netflowsight.log")
    
    # Default safe domains (fallback)
    DEFAULT_SAFE_DOMAINS: set = frozenset({
        "google.com", "www.google.com", "googleapis.com",
        "microsoft.com", "windows.com", "msftconnecttest.com",
        "apple.com", "icloud.com", "mzstatic.com",
        "amazon.com", "amazonaws.com", "cloudfront.net",
        "facebook.com", "fbcdn.net",
        "twitter.com", "twimg.com",
        "cloudflare.com", "cdnjs.cloudflare.com",
        "github.com", "githubusercontent.com",
        "linkedin.com", "licdn.com",
        "akamai.net", "akamaiedge.net",
        "fastly.net", "cloudflare.com",
    })
    
    @classmethod
    def load_safe_domains(cls) -> set[str]:
        """Load safe domains from file or use defaults."""
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
        """Check which external services are configured."""
        return {
            "abuseipdb": bool(cls.ABUSEIPDB_API_KEY),
            "virustotal": bool(cls.VIRUSTOTAL_API_KEY),
            "threatbook": bool(cls.THREATBOOK_API_KEY),
            "openai": bool(cls.OPENAI_API_KEY),
        }


settings = Settings()

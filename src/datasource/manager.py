"""
Data Source Manager for NetflowSight - With Incremental Update Support

Manages all data sources used by detection engines:
- Whitelists (domains, IPs, ports)
- Threat intelligence feeds
- Attack signatures
- Custom rules

Supports:
- Multiple source types (local files, URLs, APIs)
- Automatic updates (full, incremental, differential)
- Version control
- Health monitoring
- Conflict resolution
- Automatic strategy recommendation
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import ipaddress
import json
import logging
import re
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .strategy import StrategyRecommender, UpdateStrategy

logger = logging.getLogger(__name__)


# SSRF 防护：允许的域名白名单
ALLOWED_DOMAINS = {
    # 威胁情报源
    "raw.githubusercontent.com",
    "rules.emergingthreats.net",
    "snort.org",
    "www.snort.org",
    "abuse.ch",
    "urlhaus.abuse.ch",
    "threatfox.abuse.ch",
    "sslbl.abuse.ch",
    "feodotracker.abuse.ch",
    "pulsedive.com",
    "www.pulsedive.com",
    "otx.alienvault.com",
    "api.abuseipdb.com",
    "api.threatbook.cn",
}

# 禁止访问的私有 IP 范围
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]


def is_safe_url(url: str) -> tuple[bool, str]:
    """
    验证 URL 是否安全（SSRF 防护）。
    
    Returns:
        (is_safe, error_message)
    """
    try:
        parsed = urlparse(url)
        
        # 检查协议
        if parsed.scheme not in ('http', 'https'):
            return False, f"不允许的协议: {parsed.scheme}"
        
        # 检查域名
        hostname = parsed.hostname
        if not hostname:
            return False, "URL 缺少主机名"
        
        # 检查是否在白名单中
        if hostname not in ALLOWED_DOMAINS:
            return False, f"域名不在白名单中: {hostname}"
        
        # 检查是否是 IP 地址
        try:
            ip = ipaddress.ip_address(hostname)
            # 检查是否是私有 IP
            for private_range in PRIVATE_IP_RANGES:
                if ip in private_range:
                    return False, f"禁止访问私有 IP: {hostname}"
        except ValueError:
            # 不是 IP 地址，是域名，已经过白名单检查
            pass
        
        return True, ""
        
    except Exception as e:
        return False, f"URL 解析失败: {e}"


class DataSourceType(str, Enum):
    """Types of data sources."""
    LOCAL_FILE = "local_file"
    REMOTE_URL = "remote_url"
    API = "api"
    DNSBL = "dnsbl"
    GENERATED = "generated"


class DataSourceCategory(str, Enum):
    """Categories of data."""
    WHITELIST_DOMAINS = "whitelist_domains"
    WHITELIST_IPS = "whitelist_ips"
    WHITELIST_PORTS = "whitelist_ports"
    THREAT_IPS = "threat_ips"
    THREAT_DOMAINS = "threat_domains"
    THREAT_URLS = "threat_urls"
    ATTACK_SIGNATURES = "attack_signatures"
    SUSPICIOUS_UA = "suspicious_user_agents"
    PHISHING_KEYWORDS = "phishing_keywords"
    SUSPICIOUS_TLDS = "suspicious_tlds"


@dataclass
class DataSource:
    """Represents a single data source."""
    name: str
    category: DataSourceCategory
    source_type: DataSourceType
    url_or_path: str
    update_interval_hours: int = 24
    enabled: bool = True
    format: str = "text"
    update_strategy: UpdateStrategy = UpdateStrategy.ETAG_CHECK

    # Incremental update config
    incremental_url_template: str | None = None  # e.g., "https://example.com/data?since={last_updated}"
    incremental_window_hours: int = 24  # Max hours to look back for incremental updates
    cleanup_expired: bool = True  # Whether to cleanup expired items
    expiry_hours: int = 168  # Items expire after this many hours (for incremental sources)

    # CSV Parsing config
    skip_headers: bool = False  # Skip first row if CSV
    csv_column_index: int = 0   # Index of column to extract from CSV

    # State
    version: str = ""
    last_updated: str | None = None
    last_hash: str = ""
    item_count: int = 0
    health_status: str = "unknown"
    error_message: str | None = None
    total_updates: int = 0
    last_update_duration_ms: float = 0.0

    # Data
    items: set[str] = field(default_factory=set)
    item_timestamps: dict[str, str] = field(default_factory=dict)  # item -> when it was added
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "source_type": self.source_type.value,
            "url_or_path": self.url_or_path,
            "update_interval_hours": self.update_interval_hours,
            "enabled": self.enabled,
            "format": self.format,
            "update_strategy": self.update_strategy.value,
            "skip_headers": self.skip_headers,
            "csv_column_index": self.csv_column_index,
            "version": self.version,
            "last_updated": self.last_updated,
            "item_count": self.item_count,
            "health_status": self.health_status,
            "error_message": self.error_message,
            "total_updates": self.total_updates,
        }


class DataSourceManager:
    """
    Central manager for all data sources.

    Supports:
    - Full updates
    - ETag-based conditional updates
    - Time-window incremental updates
    - API-based incremental updates
    - Version control and rollback
    """

    # Default update strategies
    DEFAULT_STRATEGIES: dict[str, UpdateStrategy] = {
        "spamhaus_drop": UpdateStrategy.ETAG_CHECK,
        "alexa_top_domains": UpdateStrategy.ETAG_CHECK,
        "urlhaus_malicious": UpdateStrategy.TIME_WINDOW,
        "phishtank_urls": UpdateStrategy.TIME_WINDOW,
        "threatfox_iocs": UpdateStrategy.TIME_WINDOW,
    }

    def __init__(
        self,
        data_dir: str = "data/sources",
        auto_load_state: bool = True,
        auto_update_on_start: bool = False,
        auto_detect_strategies: bool = False,
        interactive: bool = True,
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self._sources: dict[str, DataSource] = {}
        self._combined_data: dict[DataSourceCategory, set[str]] = {}
        self._update_history: list[dict] = []
        self._recommender = StrategyRecommender()
        self._interactive = interactive

        # Initialize default sources
        self._register_default_sources()

        # Auto-detect and apply optimal strategies
        if auto_detect_strategies:
            self.auto_optimize_strategies()

        # Check if this is the first run
        state_path = self.data_dir / "state.json"
        is_first_run = not state_path.exists()

        # Auto-load cached state
        if auto_load_state:
            self.load_state()

        # Ask for update on every run (including first run)
        if self._interactive:
            self._ask_and_update()
        elif is_first_run:
            # Non-interactive first run: auto-update
            logger.info("First run detected: Automatically updating data sources...")
            try:
                self.update_all()
                logger.info("Initial data source update complete")
            except Exception as e:
                logger.warning(f"Initial update failed: {e}")
        else:
            # Non-interactive subsequent runs: use cached data
            logger.debug("Using cached data sources (non-interactive mode)")

    def _register_default_sources(self) -> None:
        """Register built-in default data sources."""
        defaults = [
            # ==========================================
            # 内置安全域名白名单
            # ==========================================
            DataSource(
                name="builtin_safe_domains",
                category=DataSourceCategory.WHITELIST_DOMAINS,
                source_type=DataSourceType.GENERATED,
                url_or_path="builtin",
                update_strategy=UpdateStrategy.NONE,
                update_interval_hours=0,
                items={
                    # 国际常用服务
                    "google.com", "www.google.com", "googleapis.com", "gstatic.com",
                    "microsoft.com", "windows.com", "office.com", "windows.net",
                    "windowsupdate.com", "azure.com", "azureedge.net", "live.com",
                    "outlook.com", "teams.microsoft.com", "facebook.com", "fbcdn.net",
                    "cloudflare.com", "cloudfront.net", "amazonaws.com", "apple.com",
                    "icloud.com", "github.com", "linkedin.com", "twitter.com",
                    # 国内常用服务
                    "baidu.com", "www.baidu.com", "bdstatic.com", "baidubce.com",
                    "aliyun.com", "aliyuncs.com", "alipay.com", "alipayobjects.com",
                    "taobao.com", "tmall.com", "alicdn.com", "tbcdn.cn",
                    "qq.com", "qqzhi.com", "qlogo.cn", "gtimg.cn", "qpic.cn",
                    "weixin.qq.com", "wx.qq.com", "work.weixin.qq.com",
                    "163.com", "126.net", "127.net", "netease.com",
                    "sina.com.cn", "sinaimg.cn", "weibo.com", "weibo.cn",
                    "jd.com", "360buyimg.com", "jdcloud.com",
                    "huawei.com", "hicloud.com", "vmall.com",
                    "mi.com", "miui.com", "xiaomi.com", "xiaomi.cn",
                    "douyin.com", "douyinvod.com", "douyinpic.com", "douyinstatic.com",
                    "kuaishou.com", "kuaishouzt.com", "gifshow.com",
                    "bilibili.com", "bilivideo.com", "biliapi.net", "hdslb.com",
                    "zhihu.com", "zhimg.com",
                    "tencent.com", "tencent-cloud.net", "qcloud.com",
                    "cdn-go.cn", "gtimg.com", "idqqimg.com",
                    # 阿里云 CDN/云服务
                    "alikunlun.com", "alikunlun.net", "cdngslb.com", "alibabacloud.com",
                    # 腾讯云 CDN/云服务
                    "myqcloud.com", "tencentclb.com", "tencentcos.cn",
                    # 华为云 CDN/云服务
                    "huaweicloud.com", "myhuaweicloud.com", "huaweicloud.cn", "hwcdn.net",
                },
                version="3.0.0",
                last_updated=datetime.now().isoformat(),
                health_status="healthy",
            ),
            # ==========================================
            # 内置可疑 User-Agent
            # ==========================================
            DataSource(
                name="builtin_suspicious_ua",
                category=DataSourceCategory.SUSPICIOUS_UA,
                source_type=DataSourceType.GENERATED,
                url_or_path="builtin",
                update_strategy=UpdateStrategy.NONE,
                update_interval_hours=0,
                items={
                    "python-requests", "python-urllib", "python-httpx",
                    "curl", "wget", "powershell", "pwsh",
                    "go-http-client", "java/", "libwww-perl",
                    "nikto", "sqlmap", "nmap", "masscan", "dirbuster",
                    "gobuster", "wfuzz", "hydra", "metasploit",
                },
                version="1.0.0",
                last_updated=datetime.now().isoformat(),
                health_status="healthy",
            ),
            # ==========================================
            # 内置钓鱼关键词
            # ==========================================
            DataSource(
                name="builtin_phishing_keywords",
                category=DataSourceCategory.PHISHING_KEYWORDS,
                source_type=DataSourceType.GENERATED,
                url_or_path="builtin",
                update_strategy=UpdateStrategy.NONE,
                update_interval_hours=0,
                items={
                    "login", "secure", "account", "verify", "update", "confirm",
                    "banking", "paypal", "apple-id", "microsoft-account", "signin",
                    "password-reset", "credential", "authenticate", "authorize",
                    # 中文钓鱼关键词
                    "登录", "验证", "更新", "确认", "安全中心", "账号异常",
                    "冻结", "解冻", "重置密码", "实名认证", "人脸识别",
                },
                version="2.0.0",
                last_updated=datetime.now().isoformat(),
                health_status="healthy",
            ),
            # ==========================================
            # 远程威胁情报源（国际）
            # ==========================================
            # OpenPhish (钓鱼网站)
            DataSource(
                name="openphish_feed",
                category=DataSourceCategory.THREAT_DOMAINS,
                source_type=DataSourceType.REMOTE_URL,
                url_or_path="https://openphish.com/feed.txt",
                update_strategy=UpdateStrategy.ETAG_CHECK,
                update_interval_hours=4,
                expiry_hours=12,
                format="text",
            ),
            # Spamhaus DROP (恶意 IP 段)
            DataSource(
                name="spamhaus_drop",
                category=DataSourceCategory.THREAT_IPS,
                source_type=DataSourceType.REMOTE_URL,
                url_or_path="https://www.spamhaus.org/drop/drop.txt",
                update_strategy=UpdateStrategy.ETAG_CHECK,
                update_interval_hours=24,
                expiry_hours=0,
                format="text",
            ),
            # URLhaus (恶意 URL)
            DataSource(
                name="urlhaus_malicious_gz",
                category=DataSourceCategory.THREAT_URLS,
                source_type=DataSourceType.REMOTE_URL,
                url_or_path="https://urlhaus.abuse.ch/downloads/csv_recent/",
                update_strategy=UpdateStrategy.ETAG_CHECK,
                format="csv",
                skip_headers=True,
                csv_column_index=2,
                update_interval_hours=24,
                expiry_hours=168,
            ),
            # ==========================================
            # 免费公开威胁情报源（推荐）
            # ==========================================
            # Abuse.ch URLhaus 恶意域名（免费）
            DataSource(
                name="urlhaus_domains",
                category=DataSourceCategory.THREAT_DOMAINS,
                source_type=DataSourceType.REMOTE_URL,
                url_or_path="https://urlhaus.abuse.ch/downloads/hostfile/",
                update_strategy=UpdateStrategy.ETAG_CHECK,
                update_interval_hours=12,
                expiry_hours=24,
                format="text",
            ),
            # ==========================================
            # 恶意 IP 黑名单
            # ==========================================
            # Spamhaus DROP Extended (扩展恶意 IP 段)
            DataSource(
                name="spamhaus_drop_extended",
                category=DataSourceCategory.THREAT_IPS,
                source_type=DataSourceType.REMOTE_URL,
                url_or_path="https://www.spamhaus.org/drop/edrop.txt",
                update_strategy=UpdateStrategy.ETAG_CHECK,
                update_interval_hours=24,
                expiry_hours=0,
                format="text",
            ),
            # Blocklist.de (攻击 IP 列表)
            DataSource(
                name="blocklist_de",
                category=DataSourceCategory.THREAT_IPS,
                source_type=DataSourceType.REMOTE_URL,
                url_or_path="https://lists.blocklist.de/lists/all.txt",
                update_strategy=UpdateStrategy.ETAG_CHECK,
                update_interval_hours=6,
                expiry_hours=24,
                format="text",
            ),
            # FireHOL Level 1 (高可信度恶意 IP)
            DataSource(
                name="firehol_level1",
                category=DataSourceCategory.THREAT_IPS,
                source_type=DataSourceType.REMOTE_URL,
                url_or_path="https://iplists.firehol.org/files/firehol_level1.netset",
                update_strategy=UpdateStrategy.ETAG_CHECK,
                update_interval_hours=24,
                expiry_hours=48,
                format="text",
            ),
        ]

        for source in defaults:
            self._sources[source.name] = source
            source.item_count = len(source.items)
            # Track when built-in items were "added"
            now = datetime.now().isoformat()
            source.item_timestamps = dict.fromkeys(source.items, now)
            self._merge_source_data(source)

        logger.info(f"Registered {len(defaults)} built-in data sources")

    def add_source(self, source: DataSource) -> None:
        """Add a new data source."""
        self._sources[source.name] = source

        # Set default strategy if not specified
        if source.update_strategy == UpdateStrategy.ETAG_CHECK:
            source.update_strategy = self.DEFAULT_STRATEGIES.get(source.name, UpdateStrategy.ETAG_CHECK)

        # If local file, load it immediately
        if source.source_type == DataSourceType.LOCAL_FILE:
            self._update_local_source(source)
        else:
            self._merge_source_data(source)

        logger.info(f"Added data source: {source.name} ({source.source_type.value}, strategy: {source.update_strategy.value})")

    def remove_source(self, name: str) -> bool:
        """Remove a data source."""
        if name in self._sources:
            source = self._sources.pop(name)
            self._unmerge_source_data(source)
            logger.info(f"Removed data source: {name}")
            return True
        return False

    def enable_source(self, name: str) -> bool:
        """Enable a data source."""
        if name in self._sources:
            self._sources[name].enabled = True
            self._merge_source_data(self._sources[name])
            return True
        return False

    def disable_source(self, name: str) -> bool:
        """Disable a data source."""
        if name in self._sources:
            source = self._sources[name]
            source.enabled = False
            self._unmerge_source_data(source)
            return True
        return False

    def get_source(self, name: str) -> DataSource | None:
        """Get a data source by name."""
        return self._sources.get(name)

    def list_sources(self) -> list[dict[str, Any]]:
        """List all data sources with status."""
        return [s.to_dict() for s in self._sources.values()]

    def lookup(self, category: DataSourceCategory, value: str) -> bool:
        """
        Check if a value exists in a category's combined data.

        Supports:
        - Exact match
        - Suffix match (for domains)
        - Substring match (for UAs, keywords)
        - Prefix match (for IPs)
        """
        combined = self._combined_data.get(category, set())

        if value in combined:
            return True

        value_lower = value.lower()

        if category == DataSourceCategory.WHITELIST_DOMAINS:
            for item in combined:
                # Exact match or proper domain suffix match (not substring)
                if value_lower == item or value_lower.endswith("." + item):
                    return True

        if category == DataSourceCategory.WHITELIST_IPS:
            for item in combined:
                if value.startswith(item):
                    return True

        if category == DataSourceCategory.SUSPICIOUS_UA:
            for item in combined:
                if item in value_lower:
                    return True

        if category == DataSourceCategory.PHISHING_KEYWORDS:
            for item in combined:
                if item in value_lower:
                    return True

        return False

    def get_items(self, category: DataSourceCategory) -> set[str]:
        """Get all items in a category."""
        return self._combined_data.get(category, set()).copy()

    def _ask_and_update(self) -> None:
        """
        Interactively ask user if they want to update data sources.
        Shows which sources need update based on update_interval_hours.
        """
        try:
            now = datetime.now()
            remote_sources = [
                s for s in self._sources.values()
                if s.enabled and s.source_type == DataSourceType.REMOTE_URL
            ]

            # Check which sources need update
            sources_needing_update = []
            for s in remote_sources:
                if not s.last_updated:
                    sources_needing_update.append((s, "从未更新"))
                else:
                    try:
                        last_update = datetime.fromisoformat(s.last_updated)
                        hours_since = (now - last_update).total_seconds() / 3600
                        if hours_since >= s.update_interval_hours:
                            sources_needing_update.append((s, f"{hours_since:.1f}h 前"))
                    except ValueError:
                        sources_needing_update.append((s, "时间解析失败"))

            print("\n" + "=" * 60)
            print("📦 威胁情报数据源更新检查")
            print("=" * 60)

            # Show last overall update
            if self._update_history:
                last_update = self._update_history[-1].get("timestamp")
                print(f"上次更新: {last_update}")
            else:
                print("上次更新: 从未")

            print(f"远程数据源: {len(remote_sources)} 个")
            print(f"需要更新: {len(sources_needing_update)} 个")
            print()

            # Show sources needing update
            if sources_needing_update:
                print("需要更新的数据源:")
                for s, time_info in sources_needing_update:
                    interval = f"{s.update_interval_hours}h" if s.update_interval_hours > 0 else "手动"
                    print(f"  • {s.name}: {time_info} (间隔: {interval})")
                print()
                print("是否更新? [Y/n]: ", end="", flush=True)
            else:
                print("✅ 所有数据源都在更新间隔内")
                print("是否强制更新所有数据源? [y/N]: ", end="", flush=True)

            choice = input().strip().lower()

            if choice in ("", "y", "yes") and sources_needing_update:
                print("\n🔄 正在更新数据源...")
                results = self.update_all(force=False)
                success = sum(1 for v in results.values() if v)
                total = len(list(remote_sources))
                print(f"✅ 更新完成: {success}/{total} 个数据源成功")
            elif choice in ("y", "yes"):
                print("\n🔄 正在强制更新所有数据源...")
                results = self.update_all(force=True)
                success = sum(1 for v in results.values() if v)
                total = len(list(remote_sources))
                print(f"✅ 更新完成: {success}/{total} 个数据源成功")
            else:
                print("⏭️ 跳过更新，使用缓存数据")

            print("=" * 60 + "\n")

        except (EOFError, KeyboardInterrupt):
            # Non-interactive fallback
            logger.info("Non-interactive mode: skipping update check")
        except Exception as e:
            logger.warning(f"Interactive update failed: {e}")

    def update_all(self, force: bool = False) -> dict[str, bool]:
        """
        Update all enabled remote data sources.

        Args:
            force: If True, update all sources regardless of update_interval_hours.
                   If False, only update sources that need update based on interval.

        Uses the configured strategy for each source:
        - NONE: Skip update (built-in sources)
        - ETAG_CHECK: HTTP conditional request
        - TIME_WINDOW: Download only recent changes
        - API_INCREMENTAL: Use API with since parameter
        - FULL: Always download full dataset

        Returns:
            Dict of source name -> success status
        """
        results = {}
        now = datetime.now()

        for name, source in self._sources.items():
            if not source.enabled:
                results[name] = True
                continue

            if source.source_type == DataSourceType.GENERATED:
                results[name] = True
                continue

            # Check if update is needed based on interval
            if not force and source.update_interval_hours > 0 and source.last_updated:
                try:
                    last_update = datetime.fromisoformat(source.last_updated)
                    hours_since = (now - last_update).total_seconds() / 3600
                    if hours_since < source.update_interval_hours:
                        logger.debug(
                            f"Skipping {name}: updated {hours_since:.1f}h ago "
                            f"(interval: {source.update_interval_hours}h)"
                        )
                        results[name] = True
                        continue
                except ValueError:
                    pass  # Invalid timestamp, proceed with update

            start_time = time.time()
            try:
                if source.source_type == DataSourceType.LOCAL_FILE:
                    results[name] = self._update_local_source(source)
                elif source.source_type == DataSourceType.REMOTE_URL:
                    results[name] = self._update_remote_source(source)
                elif source.source_type == DataSourceType.API:
                    results[name] = self._update_api_source(source)
            except Exception as e:
                logger.error(f"Failed to update {name}: {e}")
                results[name] = False
            finally:
                source.last_update_duration_ms = (time.time() - start_time) * 1000
                source.total_updates += 1

        self._update_history.append({
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "success_count": sum(1 for v in results.values() if v),
            "total_count": len(results),
        })

        # Save state after update
        self.save_state()

        updated_count = sum(1 for name, v in results.items()
                           if v and self._sources[name].source_type == DataSourceType.REMOTE_URL)
        logger.info(
            f"Data source update complete: "
            f"{updated_count} sources updated"
        )

        return results

    def update_source(self, name: str) -> bool:
        """Update a specific data source."""
        source = self._sources.get(name)
        if not source or not source.enabled:
            return False

        start_time = time.time()
        try:
            if source.source_type == DataSourceType.LOCAL_FILE:
                return self._update_local_source(source)
            elif source.source_type == DataSourceType.REMOTE_URL:
                return self._update_remote_source(source)
            elif source.source_type == DataSourceType.API:
                return self._update_api_source(source)
        except Exception as e:
            logger.error(f"Failed to update {name}: {e}")
            source.health_status = "unhealthy"
            source.error_message = str(e)
            return False
        finally:
            source.last_update_duration_ms = (time.time() - start_time) * 1000
            source.total_updates += 1

        return True

    def _update_local_source(self, source: DataSource) -> bool:
        """Update from local文件."""
        try:
            path = Path(source.url_or_path)
            if not path.is_absolute():
                path = Path(self.data_dir) / source.url_or_path

            if not path.exists():
                source.health_status = "unhealthy"
                source.error_message = f"File not found: {path}"
                return False

            items = self._load_file(path, source.format)
            self._apply_update(source, items, is_incremental=False)
            return True
        except Exception as e:
            source.health_status = "unhealthy"
            source.error_message = str(e)
            return False

    def _update_remote_source(self, source: DataSource) -> bool:
        """Update from remote URL using configured strategy."""
        strategy = source.update_strategy

        if strategy == UpdateStrategy.TIME_WINDOW:
            return self._update_with_time_window(source)
        elif strategy == UpdateStrategy.DIFFERENTIAL:
            return self._update_with_differential(source)
        else:
            # Default: ETag check with full download
            return self._update_with_etag(source)

    def _fetch_and_decompress(self, url: str, last_hash: str = "") -> tuple[str | None, str]:
        """
        Download remote file and automatically handle gzip/zip decompression.
        Returns: (content_str, etag) or (None, etag) if 304 Not Modified.
        """
        # SSRF 防护：验证 URL 安全性
        is_safe, error_msg = is_safe_url(url)
        if not is_safe:
            logger.warning(f"SSRF 防护: 拒绝访问不安全的 URL: {url} - {error_msg}")
            raise ValueError(f"不安全的 URL: {error_msg}")
        
        req = Request(url)
        req.add_header("User-Agent", "NetflowSight/1.0.0 (Threat Intel)")
        req.add_header("Accept-Encoding", "gzip, deflate")
        if last_hash:
            req.add_header("If-None-Match", last_hash)

        try:
            with urlopen(req, timeout=60) as response:
                etag = response.headers.get("ETag", response.headers.get("Last-Modified", ""))
                if etag == last_hash:
                    return None, etag  # Not Modified

                raw_data = response.read()

                # 1. Auto-detect GZIP
                if url.endswith(".gz") or response.headers.get("Content-Encoding") == "gzip":
                    try:
                        with gzip.GzipFile(fileobj=io.BytesIO(raw_data)) as f:
                            return f.read().decode("utf-8", errors="ignore"), etag
                    except Exception as e:
                        logger.error(f"Gzip decompression failed for {url}: {e}")
                        raise

                # 2. Auto-detect ZIP
                if url.endswith(".zip"):
                    try:
                        with zipfile.ZipFile(io.BytesIO(raw_data)) as z:
                            first_file = z.namelist()[0]
                            return z.read(first_file).decode("utf-8", errors="ignore"), etag
                    except Exception as e:
                        logger.warning(f"Zip decompression failed: {e}")

                # 3. Plain text fallback
                return raw_data.decode("utf-8", errors="ignore"), etag
        except HTTPError as e:
            if e.code == 304:
                return None, last_hash
            raise
        except Exception:
            raise

    def _parse_csv_content(self, content: str, source: DataSource) -> set[str]:
        """Parse CSV content, handling headers and specific columns."""
        items = set()
        try:
            reader = csv.reader(io.StringIO(content))
            for i, row in enumerate(reader):
                if source.skip_headers and i == 0:
                    continue
                if row and len(row) > source.csv_column_index:
                    val = row[source.csv_column_index].strip()
                    if val and not val.startswith("#"):
                        items.add(val)
        except Exception as e:
            logger.error(f"Failed to parse CSV content for {source.name}: {e}")
        return items

    def _update_with_etag(self, source: DataSource) -> bool:
        """Update using HTTP ETag conditional request."""
        try:
            content, etag = self._fetch_and_decompress(source.url_or_path, source.last_hash)
            if content is None:
                logger.debug(f"Source {source.name} unchanged (ETag match)")
                return True

            # Determine parsing method
            if source.format == "csv":
                items = self._parse_csv_content(content, source)
            else:
                items = self._parse_content(content, source.format, source)

            source.last_hash = etag
            self._apply_update(source, items, is_incremental=False)
            return True
        except HTTPError as e:
            if e.code == 304:
                return True
            source.health_status = "unhealthy"
            source.error_message = f"HTTP {e.code}: {e.reason}"
            return False
        except Exception as e:
            source.health_status = "unhealthy"
            source.error_message = str(e)
            return False

    def _update_with_time_window(self, source: DataSource) -> bool:
        """
        Update using time-window incremental download.

        Only downloads items added since last update.
        Falls back to full update if incremental fails.
        """
        # If no last update time, do full update
        if not source.last_updated:
            logger.info(f"Source {source.name}: First run, doing full update")
            return self._update_with_etag(source)

        try:
            # Calculate time window
            last_update = datetime.fromisoformat(source.last_updated)
            hours_since = (datetime.now() - last_update).total_seconds() / 3600

            # If within window and incremental URL template is configured, try incremental
            if hours_since < source.incremental_window_hours and source.incremental_url_template:
                # Build incremental URL
                url = source.incremental_url_template.format(
                    last_updated=source.last_updated,
                    hours_since=int(hours_since),
                    since_timestamp=int(last_update.timestamp()),
                )

                logger.info(f"Source {source.name}: Incremental update (last: {hours_since:.1f}h ago)")
                return self._update_incremental_from_url(source, url)
            else:
                # Window too large or no template, do full update
                if hours_since >= source.incremental_window_hours:
                    logger.info(f"Source {source.name}: Window too large ({hours_since:.1f}h), full update")
                else:
                    logger.info(f"Source {source.name}: No incremental URL template, full update")
                return self._update_with_etag(source)
        except Exception as e:
            logger.warning(f"Source {source.name}: Incremental failed ({e}), falling back to full")
            return self._update_with_etag(source)

    def _update_incremental_from_url(self, source: DataSource, url: str) -> bool:
        """
        Download incremental data from URL and merge.

        Incremental data can be:
        1. List of new items only (additive)
        2. List with +/- prefixes (differential: +new, -removed)
        """
        try:
            req = Request(url)
            req.add_header("User-Agent", "NetflowSight/1.0.0 (Incremental)")

            with urlopen(req, timeout=30) as response:
                content = response.read().decode("utf-8")
                new_items = self._parse_content(content, source.format, source)

                if not new_items:
                    logger.debug(f"Source {source.name}: No new items")
                    return True

                # Check if differential format (+/- prefixes)
                has_diff_format = any(item.startswith(("+", "-")) for item in new_items if item)

                old_count = len(source.items)

                if has_diff_format:
                    # Differential update
                    added = 0
                    removed = 0
                    for item in new_items:
                        if not item:
                            continue
                        if item.startswith("+"):
                            source.items.add(item[1:])
                            source.item_timestamps[item[1:]] = datetime.now().isoformat()
                            added += 1
                        elif item.startswith("-"):
                            source.items.discard(item[1:])
                            source.item_timestamps.pop(item[1:], None)
                            removed += 1

                    logger.info(
                        f"Source {source.name}: Differential update "
                        f"+{added} -{removed} (total: {len(source.items)})"
                    )
                else:
                    # Additive only
                    for item in new_items:
                        if item not in source.items:
                            source.items.add(item)
                            source.item_timestamps[item] = datetime.now().isoformat()

                    added = len(source.items) - old_count
                    logger.info(
                        f"Source {source.name}: Incremental update "
                        f"+{added} items (total: {len(source.items)})"
                    )

                # Cleanup expired items
                if source.cleanup_expired:
                    cleaned = self._cleanup_expired_items(source)
                    if cleaned > 0:
                        logger.info(f"Source {source.name}: Cleaned {cleaned} expired items")

                source.item_count = len(source.items)
                source.version = self._compute_version(source.items)
                source.last_updated = datetime.now().isoformat()
                source.health_status = "healthy"
                source.error_message = None

                # Re-merge
                self._unmerge_source_data(source)
                self._merge_source_data(source)

                return True
        except HTTPError as e:
            if e.code == 404:
                logger.warning(f"Source {source.name}: Incremental URL not found, fallback to full")
                return self._update_with_etag(source)
            raise
        except Exception as e:
            source.health_status = "degraded"
            source.error_message = f"Incremental update failed: {e}"
            raise

    def _update_with_differential(self, source: DataSource) -> bool:
        """
        Update using differential files.

        Expects diff files at: {base_url}/diff-{old_version}-{new_version}.ext
        Falls back to full update if diff not available.
        """
        if not source.version:
            return self._update_with_etag(source)

        # Try to find and apply diff
        # This is source-specific, so we use a generic approach
        return self._update_with_time_window(source)

    def _update_api_source(self, source: DataSource) -> bool:
        """Update from API (supports incremental via API parameters)."""
        source.health_status = "degraded"
        source.error_message = "API source not implemented yet"
        return False

    def _cleanup_expired_items(self, source: DataSource) -> int:
        """Remove items older than expiry_hours."""
        if not source.item_timestamps:
            return 0

        cutoff = datetime.now() - timedelta(hours=source.expiry_hours)
        expired = []

        for item, timestamp_str in source.item_timestamps.items():
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
                if timestamp < cutoff:
                    expired.append(item)
            except (ValueError, TypeError):
                pass

        for item in expired:
            source.items.discard(item)
            source.item_timestamps.pop(item, None)

        return len(expired)

    def _apply_update(self, source: DataSource, new_items: set[str], is_incremental: bool = False) -> None:
        """Apply new data to a source."""
        old_count = source.item_count
        old_hash = self._compute_hash(source.items)

        if is_incremental:
            # Merge new items
            for item in new_items:
                if item not in source.items:
                    source.items.add(item)
                    source.item_timestamps[item] = datetime.now().isoformat()
        else:
            # Full replacement
            source.items = new_items
            source.item_timestamps = {item: datetime.now().isoformat() for item in new_items}

        source.item_count = len(source.items)
        source.last_updated = datetime.now().isoformat()
        source.version = self._compute_version(source.items)
        source.health_status = "healthy"
        source.error_message = None

        new_hash = self._compute_hash(source.items)
        changed = old_hash != new_hash

        if changed:
            logger.info(
                f"Source {source.name} updated: "
                f"{old_count} -> {source.item_count} items"
            )
            self._unmerge_source_data(source)
            self._merge_source_data(source)

    def _merge_source_data(self, source: DataSource) -> None:
        """Merge source data into combined data."""
        category = source.category
        if category not in self._combined_data:
            self._combined_data[category] = set()
        self._combined_data[category].update(source.items)

    def _unmerge_source_data(self, source: DataSource) -> None:
        """Remove source data from combined data."""
        category = source.category
        if category in self._combined_data:
            self._combined_data[category] -= source.items

    def _load_file(self, path: Path, format: str) -> set[str]:
        """Load data from a file."""
        with open(path, encoding="utf-8") as f:
            content = f.read()
        return self._parse_content(content, format)

    def _parse_content(self, content: str, format: str, source: DataSource | None = None) -> set[str]:
        """Parse content based on format.

        Args:
            content: Raw content string
            format: Content format type
            source: Optional DataSource object for CSV column index config
        """
        items = set()

        if format == "text":
            items = {line.strip() for line in content.splitlines()
                     if line.strip() and not line.startswith("#")}

        elif format == "hosts":
            # Parse hosts file format: IP domain [domain...]
            # Extract domains, skip IP addresses
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    # Skip the IP (first part), take domains
                    for domain in parts[1:]:
                        domain = domain.strip().lower()
                        if domain and not domain.startswith("#"):
                            items.add(domain)

        elif format == "csv":
            import io
            # Use csv_column_index from source if available, default to 0
            col_index = source.csv_column_index if source else 0
            skip_headers = source.skip_headers if source else False

            reader = csv.reader(io.StringIO(content))
            for i, row in enumerate(reader):
                # Skip header row if configured
                if skip_headers and i == 0:
                    continue
                if row and len(row) > col_index:
                    val = row[col_index].strip()
                    if val and not val.startswith("#"):
                        items.add(val)

        elif format == "json":
            data = json.loads(content)
            if isinstance(data, list):
                items = {str(item).strip() for item in data if item}
            elif isinstance(data, dict):
                for key in ["items", "domains", "ips", "urls", "indicators"]:
                    if key in data and isinstance(data[key], list):
                        items = {str(item).strip() for item in data[key] if item}
                        break

        return items

    @staticmethod
    def _compute_hash(items: set[str]) -> str:
        """Compute hash of item set for change detection."""
        content = "|".join(sorted(items))
        return hashlib.md5(content.encode()).hexdigest()[:8]

    @staticmethod
    def _compute_version(items: set[str]) -> str:
        """Generate version string."""
        h = hashlib.md5("|".join(sorted(items)).encode()).hexdigest()[:6]
        return f"1.{len(items)}.{h}"

    def get_stats(self) -> dict[str, Any]:
        """Get data source statistics."""
        return {
            "total_sources": len(self._sources),
            "enabled_sources": sum(1 for s in self._sources.values() if s.enabled),
            "healthy_sources": sum(1 for s in self._sources.values() if s.health_status == "healthy"),
            "total_items": {cat.value: len(items) for cat, items in self._combined_data.items()},
            "last_update": self._update_history[-1] if self._update_history else None,
            "strategies": {
                name: source.update_strategy.value
                for name, source in self._sources.items()
            },
        }

    def export_config(self) -> dict[str, Any]:
        """Export data source configuration."""
        return {
            "version": "1.0",
            "exported_at": datetime.now().isoformat(),
            "sources": [
                {
                    "name": s.name,
                    "category": s.category.value,
                    "source_type": s.source_type.value,
                    "url_or_path": s.url_or_path,
                    "update_interval_hours": s.update_interval_hours,
                    "update_strategy": s.update_strategy.value,
                    "incremental_url_template": s.incremental_url_template,
                    "incremental_window_hours": s.incremental_window_hours,
                    "enabled": s.enabled,
                    "format": s.format,
                }
                for s in self._sources.values()
                if s.source_type != DataSourceType.GENERATED
            ],
        }

    def import_config(self, config: dict[str, Any]) -> int:
        """Import data source configuration."""
        count = 0
        for src_config in config.get("sources", []):
            try:
                source = DataSource(
                    name=src_config["name"],
                    category=DataSourceCategory(src_config["category"]),
                    source_type=DataSourceType(src_config["source_type"]),
                    url_or_path=src_config["url_or_path"],
                    update_interval_hours=src_config.get("update_interval_hours", 24),
                    update_strategy=UpdateStrategy(src_config.get("update_strategy", "etag_check")),
                    incremental_url_template=src_config.get("incremental_url_template"),
                    incremental_window_hours=src_config.get("incremental_window_hours", 24),
                    enabled=src_config.get("enabled", True),
                    format=src_config.get("format", "text"),
                )
                self.add_source(source)
                count += 1
            except Exception as e:
                logger.error(f"Failed to import source {src_config.get('name', 'unknown')}: {e}")
        return count

    def auto_optimize_strategies(self) -> dict[str, dict]:
        """
        Automatically detect source characteristics and optimize update strategies.

        Returns:
            Dict of recommendations and changes applied
        """
        logger.info("Auto-detecting optimal strategies for all sources...")
        recommendations = self._recommender.detect_all(self._sources)
        changes = self._recommender.apply_recommendations(self)

        # Log summary
        changed_count = sum(1 for v in changes.values() if v)
        logger.info(f"Strategy optimization complete: {changed_count}/{len(changes)} sources updated")

        return recommendations

    def recommend_strategies(self) -> dict[str, dict]:
        """
        Get strategy recommendations without applying them.

        Returns:
            Detailed recommendations for review
        """
        return self._recommender.detect_all(self._sources)

    def get_strategy_report(self) -> dict[str, Any]:
        """
        Get detailed report on strategy effectiveness.
        """
        report = {
            "sources": {},
            "summary": {
                "total": len(self._sources),
                "by_strategy": {},
                "avg_success_rate": 0,
            }
        }

        total_success = 0
        total_updates = 0

        for name, source in self._sources.items():
            history = self._recommender._history.get(name, [])
            success_count = sum(1 for h in history if h.get("success", True))
            etag_hits = sum(1 for h in history if h.get("etag_hit", False))

            success_rate = success_count / len(history) if history else 1.0
            etag_rate = etag_hits / len(history) if history else 0

            report["sources"][name] = {
                "current_strategy": source.update_strategy.value,
                "success_rate": round(success_rate, 2),
                "etag_hit_rate": round(etag_rate, 2),
                "total_updates": source.total_updates,
                "avg_duration_ms": round(source.last_update_duration_ms, 1),
                "recommendation": "Optimal" if success_rate > 0.9 else "Consider review",
            }

            # Aggregate by strategy
            strat = source.update_strategy.value
            if strat not in report["summary"]["by_strategy"]:
                report["summary"]["by_strategy"][strat] = {"count": 0, "avg_success": 0}
            report["summary"]["by_strategy"][strat]["count"] += 1

            total_success += success_count
            total_updates += len(history) if history else 1

        report["summary"]["avg_success_rate"] = round(
            total_success / max(total_updates, 1), 2
        )

        return report

    def save_state(self, path: str | None = None) -> str:
        """Save current state to disk (excluding large item sets)."""
        state_path = Path(path) if path else self.data_dir / "state.json"

        state = {
            "sources": {
                name: {
                    # Configuration (for recreating source)
                    "category": s.category.value,
                    "source_type": s.source_type.value,
                    "url_or_path": s.url_or_path,
                    "update_interval_hours": s.update_interval_hours,
                    "enabled": s.enabled,
                    "format": s.format,
                    "update_strategy": s.update_strategy.value,
                    "incremental_url_template": s.incremental_url_template,
                    "incremental_window_hours": s.incremental_window_hours,
                    "cleanup_expired": s.cleanup_expired,
                    "expiry_hours": s.expiry_hours,
                    # State (metadata only, not actual items)
                    "version": s.version,
                    "last_updated": s.last_updated,
                    "last_hash": s.last_hash,
                    "item_count": s.item_count,
                    "health_status": s.health_status,
                    # Items are reloaded from source on next load, not persisted
                    "total_updates": s.total_updates,
                }
                for name, s in self._sources.items()
            },
            "update_history": self._update_history[-50:],  # Keep last 50
        }

        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)

        return str(state_path)

    def load_state(self, path: str | None = None) -> bool:
        """Load state from disk (items are reloaded from sources, not from state)."""
        state_path = Path(path) if path else self.data_dir / "state.json"
        if not state_path.exists():
            return False

        try:
            with open(state_path, encoding="utf-8") as f:
                state = json.load(f)

            for name, s_state in state.get("sources", {}).items():
                # Check if source already exists
                if name in self._sources:
                    source = self._sources[name]
                    # Update existing source metadata (items stay in memory)
                    source.version = s_state.get("version", source.version)
                    source.last_updated = s_state.get("last_updated")
                    source.last_hash = s_state.get("last_hash", "")
                    source.item_count = s_state.get("item_count", 0)
                    source.health_status = s_state.get("health_status", "unknown")
                    source.total_updates = s_state.get("total_updates", 0)
                else:
                    # Create new source from saved configuration
                    try:
                        source = DataSource(
                            name=name,
                            category=DataSourceCategory(s_state.get("category", "whitelist_domains")),
                            source_type=DataSourceType(s_state.get("source_type", "remote_url")),
                            url_or_path=s_state.get("url_or_path", ""),
                            update_interval_hours=s_state.get("update_interval_hours", 24),
                            enabled=s_state.get("enabled", True),
                            format=s_state.get("format", "text"),
                            update_strategy=UpdateStrategy(s_state.get("update_strategy", "etag_check")),
                            skip_headers=s_state.get("skip_headers", False),
                            csv_column_index=s_state.get("csv_column_index", 0),
                            incremental_url_template=s_state.get("incremental_url_template"),
                            incremental_window_hours=s_state.get("incremental_window_hours", 24),
                            cleanup_expired=s_state.get("cleanup_expired", True),
                            expiry_hours=s_state.get("expiry_hours", 168),
                            version=s_state.get("version", ""),
                            last_updated=s_state.get("last_updated"),
                            last_hash=s_state.get("last_hash", ""),
                            item_count=s_state.get("item_count", 0),
                            health_status=s_state.get("health_status", "unknown"),
                            items=set(),  # Items will be loaded from source on update
                            item_timestamps={},
                            total_updates=s_state.get("total_updates", 0),
                        )
                        self._sources[name] = source
                        logger.debug(f"Restored source config from state: {name}")
                    except Exception as e:
                        logger.warning(f"Failed to restore source {name}: {e}")

            self._update_history = state.get("update_history", [])
            return True
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
            return False

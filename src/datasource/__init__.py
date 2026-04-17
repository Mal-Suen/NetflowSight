"""
Data Source Management Module

Manages all data sources used by detection engines:
- Whitelists (domains, IPs, ports)
- Threat intelligence feeds
- Attack signatures
- Custom rules

Features:
- Automatic strategy recommendation
- Incremental updates
- Version control and rollback
"""

from .manager import DataSource, DataSourceCategory, DataSourceManager, DataSourceType
from .strategy import StrategyRecommender, StrategyScore, UpdateStrategy

__all__ = [
    "DataSource",
    "DataSourceManager",
    "DataSourceType",
    "DataSourceCategory",
    "UpdateStrategy",
    "StrategyRecommender",
    "StrategyScore",
]

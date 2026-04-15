"""
手动触发数据源更新
"""
import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from datasource.manager import DataSourceManager

print("=" * 60)
print("🔄 NetflowSight 数据源更新")
print("=" * 60)

# 创建管理器（触发首次运行自动更新）
manager = DataSourceManager(
    data_dir=str(project_root / "data" / "sources"),
    auto_load_state=True,
    auto_update_on_start=True,  # 触发更新
    interactive=False,           # 非交互模式
)

# 显示所有源状态
print("\n📊 数据源状态:")
print("-" * 60)
for name, source in manager._sources.items():
    icon = {"healthy": "✅", "unhealthy": "❌", "unknown": "❓"}.get(source.health_status, "❓")
    enabled_icon = "🟢" if source.enabled else "🔴"
    print(f"{icon} {enabled_icon} {name}")
    print(f"   类别: {source.category.value}")
    print(f"   条目: {source.item_count:,}")
    print(f"   状态: {source.health_status}")
    if source.last_updated:
        print(f"   更新: {source.last_updated}")
    print()

# 统计
total = len(manager._sources)
enabled = sum(1 for s in manager._sources.values() if s.enabled)
healthy = sum(1 for s in manager._sources.values() if s.health_status == "healthy")

print("=" * 60)
print(f"📊 总计: {total} 个源, {enabled} 个启用, {healthy} 个健康")
print("=" * 60)

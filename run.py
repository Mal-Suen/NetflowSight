"""
NetflowSight 正常运行测试 - 交互模式
模拟用户正常使用数据源管理器的流程
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "src"))

from netflowsight.datasource.manager import DataSourceManager

print("=" * 60)
print("🚀 NetflowSight 正常运行测试（交互模式）")
print("=" * 60)
print()

# 1. 初始化（启动时询问是否更新）
print("[1] 初始化数据源管理器...")
print("    (配置: interactive=True, auto_update_on_start=True)")
manager = DataSourceManager(
    data_dir="data/sources",
    interactive=True,       # 启用交互
    auto_update_on_start=True, # 启动时检查更新
)
print()

# 2. 查看数据源状态
print("[2] 当前数据源状态:")
for name, source in manager._sources.items():
    if source.source_type.value != "generated":
        icon = {"healthy": "✅", "unknown": "❓"}.get(source.health_status, "⚠️")
        print(f"   {icon} {name}")
        print(f"      策略: {source.update_strategy.value} | 条目: {source.item_count}")
print()

print("=" * 60)
print("✅ 测试完成")
print("=" * 60)

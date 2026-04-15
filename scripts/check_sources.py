"""
检查黑白名单库中的数据更新状态
"""
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta

# 数据源目录
project_root = Path(__file__).resolve().parent.parent
SOURCES_DIR = project_root / "data" / "sources"
STATE_FILE = SOURCES_DIR / "state.json"

def check_sources():
    """检查所有数据源的更新状态"""
    print("=" * 70)
    print("🔍 NetflowSight 黑白名单库数据更新状态检查")
    print("=" * 70)

    if not STATE_FILE.exists():
        print("\n❌ 状态文件不存在: state.json")
        print("   从未运行过数据源更新或文件已被删除")
        return

    with open(STATE_FILE, "r", encoding="utf-8") as f:
        state = json.load(f)

    sources = state.get("sources", {})
    if not sources:
        print("\n⚠️  状态文件中没有数据源记录")
        return

    print(f"\n📊 共 {len(sources)} 个数据源")
    print(f"📁 状态文件: {STATE_FILE}")
    print(f"💾 状态文件大小: {STATE_FILE.stat().st_size / 1024:.1f} KB")

    print("\n" + "-" * 70)
    print("数据源详情:")
    print("-" * 70)

    now = datetime.now()
    healthy_count = 0
    unhealthy_count = 0
    never_updated = 0

    for name, info in sorted(sources.items()):
        source_type = info.get("source_type", "unknown")
        category = info.get("category", "unknown")
        enabled = info.get("enabled", False)
        health = info.get("health_status", "unknown")
        item_count = info.get("item_count", 0)
        last_updated = info.get("last_updated")
        version = info.get("version", "")
        update_interval = info.get("update_interval_hours", 0)
        update_strategy = info.get("update_strategy", "unknown")

        # 状态图标
        type_icon = {"generated": "📦", "remote_url": "🌐", "local_file": "📁"}.get(source_type, "❓")
        health_icon = {"healthy": "✅", "unhealthy": "❌", "unknown": "❓"}.get(health, "❓")
        enabled_icon = "🟢" if enabled else "🔴"

        # 计算更新时间
        if last_updated:
            try:
                update_time = datetime.fromisoformat(last_updated)
                age = now - update_time
                if age < timedelta(hours=1):
                    time_icon = "🟢"
                    time_str = f"{int(age.total_seconds() / 60)} 分钟前"
                elif age < timedelta(hours=24):
                    time_icon = "🟡"
                    time_str = f"{int(age.total_seconds() / 3600)} 小时前"
                elif age < timedelta(days=7):
                    time_icon = "🟠"
                    time_str = f"{age.days} 天前"
                else:
                    time_icon = "🔴"
                    time_str = f"{age.days} 天前 (过期)"
            except Exception:
                time_icon = "❓"
                time_str = "解析失败"
        else:
            time_icon = "⚪"
            time_str = "从未更新"
            never_updated += 1

        # 健康状态统计
        if health == "healthy":
            healthy_count += 1
        else:
            unhealthy_count += 1

        # 输出
        print(f"\n{type_icon} {health_icon} {enabled_icon} {name}")
        print(f"   类别: {category}")
        print(f"   策略: {update_strategy}")
        print(f"   条目数: {item_count:,}")
        print(f"   版本: {version}")
        print(f"   更新间隔: {update_interval}h" if update_interval > 0 else "   更新间隔: 手动/内置")
        print(f"   上次更新: {time_icon} {last_updated or '从未'} ({time_str})")

    print("\n" + "=" * 70)
    print("📊 汇总统计")
    print("=" * 70)
    print(f"   总数据源: {len(sources)}")
    print(f"   ✅ 健康: {healthy_count}")
    print(f"   ❌ 不健康: {unhealthy_count}")
    print(f"   ⚪ 从未更新: {never_updated}")

    # 检查远程源是否成功更新
    remote_sources = [name for name, info in sources.items() if info.get("source_type") == "remote_url"]
    updated_remotes = [name for name in remote_sources if sources[name].get("last_updated")]

    print(f"\n   🌐 远程源: {len(remote_sources)}")
    print(f"   ✅ 已更新: {len(updated_remotes)}")
    print(f"   ❌ 未更新: {len(remote_sources) - len(updated_remotes)}")

    if len(remote_sources) > len(updated_remotes):
        print("\n⚠️  以下远程源未更新:")
        for name in remote_sources:
            if name not in updated_remotes:
                print(f"   - {name}")

    # 检查状态文件大小
    if STATE_FILE.stat().st_size > 10 * 1024 * 1024:  # > 10MB
        print(f"\n⚠️  状态文件过大 ({STATE_FILE.stat().st_size / 1024 / 1024:.1f} MB)")
        print("   建议: 考虑移除 items 字段的持久化，或改用数据库")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    check_sources()

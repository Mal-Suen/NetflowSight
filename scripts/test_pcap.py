"""
端到端测试：使用真实 PCAP 文件运行 NetflowSight 分析
"""

import sys
import time
from pathlib import Path

# 添加 src 到路径
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

# 禁用 API 调用（测试环境可能没有 API key）
import os
os.environ["ABUSEIPDB_API_KEY"] = ""

PCAP_FILE = str(project_root / "data" / "samples" / "2025-06-13-traffic-analysis-exercise.pcap")


def run_analysis():
    """运行端到端分析测试"""
    from analyzer import NetflowSightAnalyzer

    print("=" * 70)
    print("NetflowSight 端到端测试")
    print("=" * 70)
    print(f"PCAP 文件: {PCAP_FILE}")
    print(f"文件大小: {Path(PCAP_FILE).stat().st_size / 1e6:.1f} MB")
    print()

    # ==========================================
    # 测试 1: 基本分析
    # ==========================================
    print("[1] 基本分析（DNS + HTTP + 隧道 + 行为 + ML）...")
    print("-" * 70)

    analyzer = NetflowSightAnalyzer(
        pcap_file=PCAP_FILE,
        enable_ml=True,
        enable_threat_intel=False,  # 禁用 API
        enable_ai=False,
        interactive=False,
    )

    t0 = time.time()
    result = analyzer.analyze()
    elapsed = time.time() - t0

    print(f"\n分析完成！耗时: {elapsed:.1f} 秒")
    print()
    print("--- 流量摘要 ---")
    print(f"  总流量数: {result.total_flows:,}")
    print(f"  总包数:   {result.total_packets:,}")
    print(f"  总字节数:  {result.total_bytes / 1e6:.1f} MB")
    print(f"  源 IP 数:  {result.unique_src_ips:,}")
    print(f"  目标 IP 数: {result.unique_dst_ips:,}")
    print()

    print("--- 威胁检测 ---")
    print(f"  总威胁数: {len(result.threats)}")
    print(f"  HIGH:     {result.high_severity_count}")
    print(f"  MEDIUM:   {result.medium_severity_count}")
    print(f"  LOW:      {result.low_severity_count}")

    if result.threats:
        print(f"\n  Top 5 威胁:")
        for i, t in enumerate(result.threats[:5], 1):
            print(f"  {i}. [{t.severity.value}] {t.description[:100]}")
    else:
        print("  (未检测到威胁)")

    print()
    print("--- ML 异常检测 ---")
    if result.ml_predictions and "error" not in result.ml_predictions:
        ml = result.ml_predictions
        print(f"  异常数: {ml.get('anomaly_count', 0)}")
        print(f"  异常率: {ml.get('anomaly_rate', 0):.2f}%")
        if ml.get('top_anomalies'):
            print(f"  Top 3 异常流量:")
            for a in ml['top_anomalies'][:3]:
                print(f"    {a.get('src_ip', '?')} -> {a.get('dst_ip', '?')}:{a.get('dst_port', '?')} "
                      f"({a.get('bidirectional_bytes', 0)/1024:.1f} KB, score={a.get('anomaly_score', 0):.3f})")
    else:
        print(f"  (ML 未启用或出错: {result.ml_predictions})")

    print()
    print("--- 检测报告 ---")
    engine_stats = {}
    for t in result.threats:
        engine = getattr(t, 'engine_name', 'unknown')
        if engine not in engine_stats:
            engine_stats[engine] = 0
        engine_stats[engine] += 1

    for engine, count in sorted(engine_stats.items(), key=lambda x: -x[1]):
        print(f"  {engine}: {count} 条")

    # ==========================================
    # 测试 2: 生成检测报告
    # ==========================================
    print()
    print("[2] 生成检测报告...")
    print("-" * 70)

    report_dir = project_root / "data" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    from report.generator import ReportGenerator
    generator = ReportGenerator(result)

    # Markdown 报告
    md_path = str(report_dir / "analysis_report.md")
    md_content = generator.generate_markdown(md_path)
    print(f"  ✅ Markdown 报告: {md_path}")
    print(f"     大小: {len(md_content):,} 字符 ({len(md_content)/1024:.1f} KB)")

    # JSON 报告
    json_path = str(report_dir / "analysis_report.json")
    json_content = generator.generate_json(json_path)
    print(f"  ✅ JSON 报告: {json_path}")
    print(f"     大小: {len(json_content):,} 字符 ({len(json_content)/1024:.1f} KB)")

    # AI 报告
    ai_path = str(report_dir / "ai_report.json")
    ai_content = generator.generate_ai_report(ai_path)
    print(f"  ✅ AI 报告: {ai_path}")
    print(f"     大小: {len(ai_content):,} 字符 ({len(ai_content)/1024:.1f} KB)")

    # 文本摘要
    text_summary = generator.generate_text_summary()
    print(f"  ✅ 文本摘要: {len(text_summary)} 字符")

    print()
    print("=" * 70)
    print("✅ 所有测试通过")
    print("=" * 70)


if __name__ == '__main__':
    # Windows 需要这个保护，因为 NFStream 使用 multiprocessing
    run_analysis()

"""命令行界面模块"""

import logging
import sys
import warnings
from datetime import datetime
from pathlib import Path

warnings.filterwarnings("ignore", message=".*numexpr.*")
warnings.filterwarnings("ignore", message=".*feature names.*")

import click
from rich.console import Console
from rich.panel import Panel

from analyzer import NetflowSightAnalyzer
from core.config import settings

console = Console()


def setup_logging(log_level: str = "INFO", log_file: str = None):
    """配置日志系统"""
    handlers = [logging.StreamHandler()]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """🔍 NetflowSight - AI 驱动的网络流量分析平台"""
    pass


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="输出报告文件路径（默认：自动生成）")
@click.option("--format", "-f", type=click.Choice(["json", "markdown", "html", "text"]), default="html", help="报告格式")
@click.option("--no-ml", is_flag=True, help="禁用 ML 异常检测")
@click.option("--no-threat-intel", is_flag=True, help="禁用威胁情报 API 查询")
@click.option("--verbose", "-v", is_flag=True, help="启用详细输出")
def analyze(pcap_file, output, format, no_ml, no_threat_intel, verbose):
    """分析 PCAP 文件并生成报告"""
    setup_logging(
        log_level="WARNING" if not verbose else "DEBUG",
        log_file=settings.LOG_FILE,
    )

    console.print(Panel.fit(
        "🔍 NetflowSight - AI 驱动的网络流量分析",
        style="bold blue",
    ))
    console.print("")

    # 初始化分析器
    analyzer = NetflowSightAnalyzer(
        pcap_file=str(pcap_file),
        enable_ml=not no_ml,
        enable_threat_intel=not no_threat_intel,
    )

    # 执行分析
    console.print("⏳ 正在分析 PCAP 文件...", style="yellow")
    result = analyzer.analyze()
    console.print("✅ 分析完成!", style="green")
    console.print("")

    # 自动生成输出路径（如果未指定）
    if not output:
        pcap_name = Path(pcap_file).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path(pcap_file).parent / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        output = str(report_dir / f"{timestamp}_{pcap_name}_report.html")
        json_output = str(report_dir / f"{timestamp}_{pcap_name}_report.json")
    elif output.endswith('.html'):
        json_output = output.replace('.html', '.json')
    elif output.endswith('.md'):
        json_output = output.replace('.md', '.json')
        output = output.replace('.md', '.html')
    elif output.endswith('.json'):
        json_output = output
        output = output.replace('.json', '.html')
    else:
        json_output = output + '.json'
        if not output.endswith('.html'):
            output = output + '.html'

    # 保存 HTML 报告
    reports = analyzer.generate_report(format="html", output_path=output, generate_ai_report=False)
    console.print(reports.get("human_report", ""), markup=False)

    # 保存 JSON 报告
    analyzer.generate_report(format="json", output_path=json_output, generate_ai_report=False)
    console.print(f"\n💾 报告已保存:")
    console.print(f"   🌐 HTML: {output}")
    console.print(f"   📋 JSON: {json_output}", style="green")

    # 显示 API 使用情况
    if analyzer.abuseipdb_detector:
        stats = analyzer.abuseipdb_detector.get_stats()
        console.print(f"\n🌐 AbuseIPDB API 使用情况:")
        console.print(f"   已查询: {stats['api_queries']} 次")
        console.print(f"   缓存命中: {stats['cache_hits']} 次")
        console.print(f"   白名单: {stats['whitelist_size']} 个 IP")
        console.print(f"   安全缓存: {stats['safe_cache_size']} 个 IP")

    if analyzer.smart_threat_detector:
        smart_stats = analyzer.smart_threat_detector.get_stats()
        console.print(f"\n🔍 微步 ThreatBook API 使用情况:")
        console.print(f"   已查询: {smart_stats['api_queries']} 次")
        console.print(f"   缓存命中: {smart_stats['cache_hits']} 次")
        console.print(f"   白名单: {smart_stats['whitelist_size']} 个域名")
        console.print(f"   安全缓存: {smart_stats['safe_cache_size']} 个域名")


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--port", "-p", type=int, help="按端口过滤")
@click.option("--ip", type=str, help="按 IP 过滤")
@click.option("--protocol", type=str, help="按协议过滤")
@click.option("--top", type=int, default=20, help="显示的流量数量")
def explore(pcap_file, port, ip, protocol, top):
    """交互式探索 PCAP 文件"""
    from .core.parser import FlowStreamAnalyzer

    console.print(f"🔍 探索 {pcap_file}...", style="blue")

    analyzer = FlowStreamAnalyzer(source=pcap_file)
    df = analyzer.parse()

    if df.empty:
        console.print("❌ 未找到任何流量", style="red")
        return

    # 应用过滤器
    if port:
        df = analyzer.filter_flows(dst_port=port)
    if ip:
        df = analyzer.filter_flows(src_ip=ip)
    if protocol:
        df = analyzer.filter_flows(protocol=protocol)

    # 显示摘要
    summary = analyzer.get_summary()
    console.print(f"📊 总流量数: {summary['total_flows']:,}", style="green")
    console.print(f"📦 过滤后流量数: {len(df):,}", style="green")
    console.print("")

    # 显示 Top 流量
    console.print(f"🔝 按字节数排序的 Top {top} 流量:", style="bold")
    top_flows = df.nlargest(top, "bidirectional_bytes")

    for i, (_, flow) in enumerate(top_flows.iterrows(), 1):
        console.print(
            f"{i:3d}. {flow['src_ip']:>15} → {flow['dst_ip']:<15} "
            f"端口: {flow['dst_port']:<6} "
            f"字节: {flow['bidirectional_bytes']:>12,} "
            f"协议: {flow.get('application_name', 'N/A')}"
        )


@cli.command()
@click.argument("ip")
def check_ip(ip):
    """查询单个 IP 的信誉信息"""
    from .intel.client import ThreatIntelligenceClient
    from .intel.cache import ThreatCache

    console.print(f"🌐 查询 IP: {ip}", style="blue")

    # 先检查缓存
    cache = ThreatCache()
    cached = cache.get(ip)

    if cached:
        console.print(f"✅ 缓存命中 (缓存时间: {cache._cache[ip]['timestamp']})")
        console.print(f"   滥用评分: {cached.abuse_score}")
        console.print(f"   国家: {cached.country_code}")
        console.print(f"   ISP: {cached.isp}")
        console.print(f"   Tor 节点: {cached.is_tor}")
        return

    # 查询 API
    client = ThreatIntelligenceClient()
    if not client.abuseipdb_key:
        console.print("❌ AbuseIPDB API 密钥未配置。请在 .env 文件中设置 ABUSEIPDB_API_KEY。", style="red")
        return

    reputation = client.check_abuseipdb(ip)
    if reputation:
        cache.set(reputation)
        console.print(f"✅ IP 信誉信息:", style="green")
        console.print(f"   滥用评分: {reputation.abuse_score}")
        console.print(f"   国家: {reputation.country_code}")
        console.print(f"   使用类型: {reputation.usage_type}")
        console.print(f"   ISP: {reputation.isp}")
        console.print(f"   域名: {reputation.domain}")
        console.print(f"   Tor 节点: {reputation.is_tor}")
        console.print(f"   举报次数: {reputation.reports_count}")
    else:
        console.print("❌ 查询 IP 信誉失败", style="red")


@cli.command()
def config():
    """显示当前配置"""
    console.print(Panel.fit("⚙️  NetflowSight 配置", style="bold blue"))
    console.print("")

    configured = settings.is_configured()

    # 显示 API 密钥配置状态
    console.print("🔑 API 密钥:")
    console.print(f"   AbuseIPDB:    {'✅ 已配置' if configured['abuseipdb'] else '❌ 未配置'}")
    console.print(f"   VirusTotal:   {'✅ 已配置' if configured['virustotal'] else '❌ 未配置'}")
    console.print(f"   ThreatBook:   {'✅ 已配置' if configured['threatbook'] else '❌ 未配置'}")
    console.print(f"   OpenAI:       {'✅ 已配置' if configured['openai'] else '❌ 未配置'}")
    console.print("")

    # 显示分析参数
    console.print("⚙️  分析参数:")
    console.print(f"   统计分析:     {settings.STATISTICAL_ANALYSIS}")
    console.print(f"   DPI 包数:     {settings.N_DISSECTIONS}")
    console.print(f"   隧道解码:     {settings.DECODE_TUNNELS}")
    console.print(f"   威胁缓存:     {settings.THREAT_CACHE_ENABLED}")
    console.print(f"   缓存有效期:   {settings.THREAT_CACHE_TTL_HOURS} 小时")
    console.print("")

    # 显示安全域名数量
    safe_domains = settings.load_safe_domains()
    console.print(f"🛡️  安全域名: 已加载 {len(safe_domains)} 个")


def main():
    """CLI 入口点"""
    cli()


if __name__ == "__main__":
    main()

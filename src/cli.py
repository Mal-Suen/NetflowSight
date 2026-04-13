"""
Command-line interface for NetflowSight
"""

import logging
import sys
import warnings
from datetime import datetime
from pathlib import Path

# Suppress third-party warnings
warnings.filterwarnings("ignore", message=".*numexpr.*")
warnings.filterwarnings("ignore", message=".*feature names.*")

import click
from rich.console import Console
from rich.panel import Panel

from analyzer import NetflowSightAnalyzer
from core.config import settings

console = Console()


def setup_logging(log_level: str = "INFO", log_file: str = None):
    """Configure logging."""
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
    """🔍 NetflowSight - AI-Powered Network Traffic Analysis"""
    pass


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output report file path (default: auto)")
@click.option("--format", "-f", type=click.Choice(["json", "markdown", "html", "text"]), default="html", help="Report format")
@click.option("--no-ml", is_flag=True, help="Disable ML anomaly detection")
@click.option("--no-threat-intel", is_flag=True, help="Disable threat intelligence API checks")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def analyze(pcap_file, output, format, no_ml, no_threat_intel, verbose):
    """Analyze a PCAP file and generate report."""
    setup_logging(
        log_level="WARNING" if not verbose else "DEBUG",
        log_file=settings.LOG_FILE,
    )

    console.print(Panel.fit(
        "🔍 NetflowSight - AI 驱动的网络流量分析",
        style="bold blue",
    ))
    console.print("")

    analyzer = NetflowSightAnalyzer(
        pcap_file=str(pcap_file),
        enable_ml=not no_ml,
        enable_threat_intel=not no_threat_intel,
    )

    console.print("⏳ 正在分析 PCAP 文件...", style="yellow")
    result = analyzer.analyze()
    console.print("✅ 分析完成!", style="green")
    console.print("")
    
    # Generate reports (HTML + JSON)
    # Auto-generate output path if not specified
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

    # Save main HTML report and get content
    reports = analyzer.generate_report(format="html", output_path=output, generate_ai_report=False)
    console.print(reports.get("human_report", ""), markup=False)

    # Save JSON report
    analyzer.generate_report(format="json", output_path=json_output, generate_ai_report=False)
    console.print(f"\n💾 报告已保存:")
    console.print(f"   🌐 HTML: {output}")
    console.print(f"   📋 JSON: {json_output}", style="green")

    # Show API usage info
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
@click.option("--port", "-p", type=int, help="Filter by port")
@click.option("--ip", type=str, help="Filter by IP")
@click.option("--protocol", type=str, help="Filter by protocol")
@click.option("--top", type=int, default=20, help="Number of top flows to show")
def explore(pcap_file, port, ip, protocol, top):
    """Explore PCAP file interactively."""
    from .core.parser import FlowStreamAnalyzer
    
    console.print(f"🔍 Exploring {pcap_file}...", style="blue")
    
    analyzer = FlowStreamAnalyzer(source=pcap_file)
    df = analyzer.parse()
    
    if df.empty:
        console.print("❌ No flows found", style="red")
        return
    
    # Apply filters
    if port:
        df = analyzer.filter_flows(dst_port=port)
    if ip:
        df = analyzer.filter_flows(src_ip=ip)
    if protocol:
        df = analyzer.filter_flows(protocol=protocol)
    
    # Show summary
    summary = analyzer.get_summary()
    console.print(f"📊 Total flows: {summary['total_flows']:,}", style="green")
    console.print(f"📦 Filtered flows: {len(df):,}", style="green")
    console.print("")
    
    # Show top flows
    console.print(f"🔝 Top {top} flows by bytes:", style="bold")
    top_flows = df.nlargest(top, "bidirectional_bytes")
    
    for i, (_, flow) in enumerate(top_flows.iterrows(), 1):
        console.print(
            f"{i:3d}. {flow['src_ip']:>15} → {flow['dst_ip']:<15} "
            f"Port: {flow['dst_port']:<6} "
            f"Bytes: {flow['bidirectional_bytes']:>12,} "
            f"Proto: {flow.get('application_name', 'N/A')}"
        )


@cli.command()
@click.argument("ip")
def check_ip(ip):
    """Check IP reputation against threat intelligence."""
    from .intel.client import ThreatIntelligenceClient
    from .intel.cache import ThreatCache
    
    console.print(f"🌐 Checking IP: {ip}", style="blue")
    
    cache = ThreatCache()
    cached = cache.get(ip)
    
    if cached:
        console.print(f"✅ Cache hit (age: {cache._cache[ip]['timestamp']})")
        console.print(f"   Abuse Score: {cached.abuse_score}")
        console.print(f"   Country: {cached.country_code}")
        console.print(f"   ISP: {cached.isp}")
        console.print(f"   Is Tor: {cached.is_tor}")
        return
    
    client = ThreatIntelligenceClient()
    if not client.abuseipdb_key:
        console.print("❌ AbuseIPDB API key not configured. Set ABUSEIPDB_API_KEY in .env file.", style="red")
        return
    
    reputation = client.check_abuseipdb(ip)
    if reputation:
        cache.set(reputation)
        console.print(f"✅ IP Reputation:", style="green")
        console.print(f"   Abuse Score: {reputation.abuse_score}")
        console.print(f"   Country: {reputation.country_code}")
        console.print(f"   Usage Type: {reputation.usage_type}")
        console.print(f"   ISP: {reputation.isp}")
        console.print(f"   Domain: {reputation.domain}")
        console.print(f"   Is Tor: {reputation.is_tor}")
        console.print(f"   Reports: {reputation.reports_count}")
    else:
        console.print("❌ Failed to check IP reputation", style="red")


@cli.command()
def config():
    """Show current configuration."""
    console.print(Panel.fit("⚙️  NetflowSight Configuration", style="bold blue"))
    console.print("")
    
    configured = settings.is_configured()
    
    console.print("🔑 API Keys:")
    console.print(f"   AbuseIPDB:    {'✅ Configured' if configured['abuseipdb'] else '❌ Not configured'}")
    console.print(f"   VirusTotal:   {'✅ Configured' if configured['virustotal'] else '❌ Not configured'}")
    console.print(f"   OpenAI:       {'✅ Configured' if configured['openai'] else '❌ Not configured'}")
    console.print("")
    
    console.print("⚙️  Settings:")
    console.print(f"   Statistical Analysis: {settings.STATISTICAL_ANALYSIS}")
    console.print(f"   N Dissections:        {settings.N_DISSECTIONS}")
    console.print(f"   Decode Tunnels:       {settings.DECODE_TUNNELS}")
    console.print(f"   Threat Cache:         {settings.THREAT_CACHE_ENABLED}")
    console.print(f"   Cache TTL:            {settings.THREAT_CACHE_TTL_HOURS} hours")
    console.print("")
    
    safe_domains = settings.load_safe_domains()
    console.print(f"🛡️  Safe Domains: {len(safe_domains)} loaded")


def main():
    """Entry point for CLI."""
    cli()


if __name__ == "__main__":
    main()

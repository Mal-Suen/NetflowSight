"""
Command-line interface for NetflowSight
"""

import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

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
@click.option("--output", "-o", type=click.Path(), help="Output report file path")
@click.option("--format", "-f", type=click.Choice(["json", "markdown", "text"]), default="text", help="Report format")
@click.option("--no-ml", is_flag=True, help="Disable ML anomaly detection")
@click.option("--no-threat-intel", is_flag=True, help="Disable threat intelligence API checks")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def analyze(pcap_file, output, format, no_ml, no_threat_intel, verbose):
    """Analyze a PCAP file and generate report."""
    setup_logging(
        log_level="DEBUG" if verbose else settings.LOG_LEVEL,
        log_file=settings.LOG_FILE,
    )
    
    console.print(Panel.fit(
        "🔍 NetflowSight - AI-Powered Network Traffic Analysis",
        style="bold blue",
    ))
    console.print("")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing PCAP file...", total=None)
        
        analyzer = NetflowSightAnalyzer(
            pcap_file=str(pcap_file),
            enable_ml=not no_ml,
            enable_threat_intel=not no_threat_intel,
        )
        
        result = analyzer.analyze()
        progress.update(task, description="Analysis complete!")
    
    console.print("")
    
    # Print summary
    report = analyzer.generate_report(format="text")
    console.print(report)
    
    # Save report if output specified
    if output:
        report_content = analyzer.generate_report(format=format, output_path=output)
        console.print(f"💾 Report saved to: {output}", style="green")


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

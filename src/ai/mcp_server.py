"""
MCP Server for AI-powered PCAP analysis
"""

import logging
from typing import Optional

import pandas as pd

from ..core.parser import FlowStreamAnalyzer
from ..core.config import settings

logger = logging.getLogger(__name__)

try:
    from fastmcp import FastMCP
    HAS_FASTMCP = True
except ImportError:
    HAS_FASTMCP = False
    logger.warning("fastmcp not installed, MCP server will be disabled")


def create_mcp_server(analyzer: FlowStreamAnalyzer) -> Optional["FastMCP"]:
    """
    Create MCP server with PCAP analysis tools.
    
    Args:
        analyzer: Initialized FlowStreamAnalyzer
        
    Returns:
        FastMCP server instance or None if fastmcp not available
    """
    if not HAS_FASTMCP:
        return None
    
    mcp = FastMCP("NetflowSight")
    
    @mcp.tool()
    def get_pcap_summary() -> dict:
        """Get summary statistics of the loaded PCAP file."""
        return analyzer.get_summary()
    
    @mcp.tool()
    def analyze_port_flows(port: int) -> dict:
        """
        Analyze traffic for a specific port.
        
        Args:
            port: Port number to analyze
        """
        flows = analyzer.filter_flows(dst_port=port)
        if flows.empty:
            return {"error": f"No flows found for port {port}"}
        
        return {
            "total_flows": len(flows),
            "unique_sources": int(flows["src_ip"].nunique()),
            "unique_destinations": int(flows["dst_ip"].nunique()),
            "total_bytes": int(flows["bidirectional_bytes"].sum()),
            "total_packets": int(flows["bidirectional_packets"].sum()),
            "top_sources": (
                flows.groupby("src_ip")["bidirectional_bytes"]
                .sum()
                .nlargest(5)
                .to_dict()
            ),
        }
    
    @mcp.tool()
    def analyze_ip(ip: str) -> dict:
        """
        Analyze traffic for a specific IP address.
        
        Args:
            ip: IP address to analyze
        """
        src_flows = analyzer.filter_flows(src_ip=ip)
        dst_flows = analyzer.filter_flows(dst_ip=ip)
        
        return {
            "as_source": {
                "flow_count": len(src_flows),
                "total_bytes": int(src_flows["bidirectional_bytes"].sum()),
                "top_destinations": (
                    src_flows.groupby("dst_ip")["bidirectional_bytes"]
                    .sum()
                    .nlargest(5)
                    .to_dict()
                ),
            },
            "as_destination": {
                "flow_count": len(dst_flows),
                "total_bytes": int(dst_flows["bidirectional_bytes"].sum()),
                "top_sources": (
                    dst_flows.groupby("src_ip")["bidirectional_bytes"]
                    .sum()
                    .nlargest(5)
                    .to_dict()
                ),
            },
        }
    
    @mcp.tool()
    def filter_by_protocol(protocol: str) -> dict:
        """
        Filter and analyze traffic by protocol.
        
        Args:
            protocol: Application protocol name (e.g., 'HTTP', 'DNS', 'TLS')
        """
        flows = analyzer.filter_flows(protocol=protocol)
        if flows.empty:
            return {"error": f"No flows found for protocol {protocol}"}
        
        return {
            "total_flows": len(flows),
            "total_bytes": int(flows["bidirectional_bytes"].sum()),
            "top_talkers": (
                flows.groupby("src_ip")["bidirectional_bytes"]
                .sum()
                .nlargest(10)
                .to_dict()
            ),
        }
    
    @mcp.tool()
    def get_large_flows(min_bytes: int = 1_000_000) -> dict:
        """
        Get flows larger than specified threshold.
        
        Args:
            min_bytes: Minimum bytes threshold (default 1MB)
        """
        flows = analyzer.filter_flows(min_bytes=min_bytes)
        if flows.empty:
            return {"message": f"No flows larger than {min_bytes} bytes"}
        
        return {
            "count": len(flows),
            "flows": flows.nlargest(20, "bidirectional_bytes")[
                ["src_ip", "dst_ip", "dst_port", "bidirectional_bytes", "bidirectional_packets"]
            ].to_dict("records"),
        }
    
    logger.info("MCP server created with 5 analysis tools")
    return mcp

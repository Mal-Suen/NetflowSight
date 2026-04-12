"""
High-performance PCAP parser using NFStream engine
"""

import logging
from pathlib import Path
from typing import Optional

import pandas as pd
from nfstream import NFStreamer

logger = logging.getLogger(__name__)


class FlowStreamAnalyzer:
    """
    Core PCAP analysis engine using NFStream's C-based high-performance parser.
    
    Features:
    - 100+ automatic flow features
    - Stream-based processing (memory efficient)
    - Multi-core parallel processing
    - DPI application recognition
    """
    
    def __init__(
        self,
        source: str,
        statistical_analysis: bool = True,
        n_dissections: int = 20,
        decode_tunnels: bool = True,
        bpf_filter: Optional[str] = None,
        idle_timeout: int = 120,
        active_timeout: int = 1800,
    ):
        """
        Initialize the FlowStreamAnalyzer.
        
        Args:
            source: Path to PCAP file or network interface
            statistical_analysis: Enable statistical feature calculation
            n_dissections: Number of packets to dissect for DPI (0-255)
            decode_tunnels: Enable tunnel protocol decoding
            bpf_filter: BPF filter string (e.g., 'tcp port 80')
            idle_timeout: Flow idle timeout in seconds
            active_timeout: Flow active timeout in seconds
        """
        self.source = source
        self._validate_source(source)
        
        self.statistical_analysis = statistical_analysis
        self.n_dissections = n_dissections
        self.decode_tunnels = decode_tunnels
        self.bpf_filter = bpf_filter
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        
        self._streamer = None
        self._df = None
        
        logger.info(f"Initialized FlowStreamAnalyzer for {source}")
    
    def _validate_source(self, source: str) -> None:
        """Validate that the source file exists or is a valid interface."""
        if Path(source).is_file():
            if not source.endswith(('.pcap', '.pcapng', '.cap')):
                logger.warning(f"Source file may not be a valid PCAP: {source}")
        else:
            logger.info(f"Source '{source}' is not a file, assuming network interface")
    
    def parse(self) -> pd.DataFrame:
        """
        Parse the PCAP file and return a DataFrame of flow records.
        
        Returns:
            pandas.DataFrame with 100+ flow features
        """
        logger.info(f"Starting PCAP parsing: {self.source}")
        
        try:
            self._streamer = NFStreamer(
                source=self.source,
                statistical_analysis=self.statistical_analysis,
                n_dissections=self.n_dissections,
                decode_tunnels=self.decode_tunnels,
                bpf_filter=self.bpf_filter,
                idle_timeout=self.idle_timeout,
                active_timeout=self.active_timeout,
            )
            
            self._df = self._streamer.to_pandas()
            
            if self._df is None or self._df.empty:
                logger.warning("No flows found in PCAP file")
                return pd.DataFrame()
            
            logger.info(
                f"Parsed {len(self._df)} flows from {self.source}"
            )
            return self._df
            
        except Exception as e:
            logger.error(f"Failed to parse PCAP: {e}")
            raise
    
    def get_dataframe(self) -> pd.DataFrame:
        """Return the parsed DataFrame (call parse() first)."""
        if self._df is None:
            raise RuntimeError("parse() must be called before get_dataframe()")
        return self._df
    
    def get_summary(self) -> dict:
        """
        Generate a summary of the parsed flows.
        
        Returns:
            Dictionary with summary statistics
        """
        if self._df is None or self._df.empty:
            return {"total_flows": 0}
        
        df = self._df
        
        summary = {
            "total_flows": len(df),
            "total_packets": int(df["bidirectional_packets"].sum()),
            "total_bytes": int(df["bidirectional_bytes"].sum()),
            "unique_src_ips": int(df["src_ip"].nunique()),
            "unique_dst_ips": int(df["dst_ip"].nunique()),
            "unique_protocols": int(df["protocol"].nunique()),
            "protocol_distribution": df["application_name"].value_counts().head(20).to_dict(),
            "top_talkers": (
                df.groupby("src_ip")["bidirectional_bytes"]
                .sum()
                .nlargest(10)
                .to_dict()
            ),
            "top_destinations": (
                df.groupby("dst_ip")["bidirectional_bytes"]
                .sum()
                .nlargest(10)
                .to_dict()
            ),
        }
        
        # Add time range if available
        if "bidirectional_first_seen_ms" in df.columns:
            summary["time_range"] = {
                "start_ms": float(df["bidirectional_first_seen_ms"].min()),
                "end_ms": float(df["bidirectional_last_seen_ms"].max()),
                "duration_ms": float(
                    df["bidirectional_last_seen_ms"].max() 
                    - df["bidirectional_first_seen_ms"].min()
                ),
            }
        
        return summary
    
    def filter_flows(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        min_bytes: int = 0,
        min_packets: int = 0,
    ) -> pd.DataFrame:
        """
        Filter flows based on criteria.
        
        Args:
            src_ip: Source IP filter
            dst_ip: Destination IP filter
            dst_port: Destination port filter
            protocol: Application protocol name filter
            min_bytes: Minimum bytes threshold
            min_packets: Minimum packets threshold
            
        Returns:
            Filtered DataFrame
        """
        if self._df is None:
            raise RuntimeError("parse() must be called before filter_flows()")
        
        df = self._df.copy()
        
        if src_ip:
            df = df[df["src_ip"] == src_ip]
        if dst_ip:
            df = df[df["dst_ip"] == dst_ip]
        if dst_port is not None:
            df = df[df["dst_port"] == dst_port]
        if protocol:
            df = df[df["application_name"] == protocol]
        if min_bytes > 0:
            df = df[df["bidirectional_bytes"] >= min_bytes]
        if min_packets > 0:
            df = df[df["bidirectional_packets"] >= min_packets]
        
        return df
    
    def get_top_anomalous_flows(
        self,
        top_n: int = 50,
        score_column: str = "anomaly_score",
    ) -> pd.DataFrame:
        """
        Get the most anomalous flows based on a scoring column.
        
        Args:
            top_n: Number of top flows to return
            score_column: Column name for anomaly scoring
            
        Returns:
            DataFrame of top anomalous flows
        """
        if self._df is None:
            raise RuntimeError("parse() must be called first")
        
        if score_column not in self._df.columns:
            logger.warning(f"Score column '{score_column}' not found, using packet count as proxy")
            return self._df.nlargest(top_n, "bidirectional_packets")
        
        return self._df.nlargest(top_n, score_column)

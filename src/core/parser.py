"""PCAP 解析模块 - 基于 NFStream 的高性能流量解析"""

import logging
from pathlib import Path
from typing import Optional

import pandas as pd
from nfstream import NFStreamer

logger = logging.getLogger(__name__)


class FlowStreamAnalyzer:
    """基于 NFStream 的核心 PCAP 分析引擎"""

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
        初始化流分析器

        Args:
            source: PCAP 文件路径或网络接口名
            statistical_analysis: 是否启用统计特征计算
            n_dissections: 用于 DPI 应用识别的包数
            decode_tunnels: 是否解码隧道协议
            bpf_filter: BPF 过滤表达式
            idle_timeout: 流空闲超时时间（秒）
            active_timeout: 流活跃超时时间（秒）
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

        logger.info(f"已初始化 FlowStreamAnalyzer: {source}")

    def _validate_source(self, source: str) -> None:
        """验证数据源有效性"""
        if Path(source).is_file():
            if not source.endswith(('.pcap', '.pcapng', '.cap')):
                logger.warning(f"源文件可能不是有效的 PCAP 格式: {source}")
        else:
            logger.info(f"源 '{source}' 不是文件，假设为网络接口")

    def parse(self) -> pd.DataFrame:
        """解析 PCAP 文件并返回流记录 DataFrame"""
        logger.info(f"开始解析 PCAP: {self.source}")

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
                logger.warning("PCAP 文件中未找到任何流")
                return pd.DataFrame()

            logger.info(f"解析完成: {len(self._df)} 个流")
            return self._df

        except Exception as e:
            logger.error(f"PCAP 解析失败: {e}")
            raise

    def get_dataframe(self) -> pd.DataFrame:
        """获取已解析的 DataFrame"""
        if self._df is None:
            raise RuntimeError("必须先调用 parse() 方法")
        return self._df

    def get_summary(self) -> dict:
        """生成流量摘要统计"""
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
            "top_talkers": df.groupby("src_ip")["bidirectional_bytes"].sum().nlargest(10).to_dict(),
            "top_destinations": df.groupby("dst_ip")["bidirectional_bytes"].sum().nlargest(10).to_dict(),
        }

        if "bidirectional_first_seen_ms" in df.columns:
            summary["time_range"] = {
                "start_ms": float(df["bidirectional_first_seen_ms"].min()),
                "end_ms": float(df["bidirectional_last_seen_ms"].max()),
                "duration_ms": float(df["bidirectional_last_seen_ms"].max() - df["bidirectional_first_seen_ms"].min()),
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
        """按条件筛选流记录"""
        if self._df is None:
            raise RuntimeError("必须先调用 parse() 方法")

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

    def get_top_anomalous_flows(self, top_n: int = 50, score_column: str = "anomaly_score") -> pd.DataFrame:
        """获取最异常的流记录"""
        if self._df is None:
            raise RuntimeError("必须先调用 parse() 方法")

        if score_column not in self._df.columns:
            return self._df.nlargest(top_n, "bidirectional_packets")
        return self._df.nlargest(top_n, score_column)

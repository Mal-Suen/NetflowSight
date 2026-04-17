"""
Network Topology Generator
Generates node and link data for visualization (e.g., Echarts).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import pandas as pd

# Pre-compiled regex patterns for performance
_IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')


def get_topology_data(df: pd.DataFrame, min_bytes: int = 1000) -> dict[str, Any]:
    """
    全量拓扑：提取所有通信关系。
    """
    return _build_topology(df, min_bytes=min_bytes, highlight_ips=None, highlight_domains=None)


def get_threat_topology(df: pd.DataFrame, threat_ips: set[str] | None = None, threat_domains: set[str] | None = None) -> dict[str, Any]:
    """
    情报威胁拓扑：仅展示命中情报库（恶意 IP/域名）的关系。
    """
    return _build_topology(df, min_bytes=0, highlight_ips=threat_ips, highlight_domains=threat_domains)


def get_anomaly_topology(df: pd.DataFrame, alert_ips: set[str] | None = None, alert_domains: set[str] | None = None) -> dict[str, Any]:
    """
    异常拓扑：展示所有检测引擎发现的高危/中危异常行为涉及的关系。
    不仅显示 IP，还显示可疑域名。
    """
    return _build_topology(df, min_bytes=0, highlight_ips=alert_ips, highlight_domains=alert_domains)


def extract_alert_iocs_from_threats(threats: list[dict]) -> tuple[set[str], set[str]]:
    """
    从检测引擎的威胁结果中提取所有涉及的 IP 地址和域名。
    """
    ips = set()
    domains = set()

    # 简单的域名校验：必须包含至少一个点，且不以点结尾，且不是 IP
    def is_valid_domain(s: str) -> bool:
        s = s.strip().lower()
        if not s or '.' not in s or s.endswith('.'):
            return False
        # 排除明显的 IP 地址
        return not (_IP_PATTERN.match(s) and s.count('.') == 3)

    for threat in threats:
        # 1. 从证据字段提取
        evidence = threat.get('evidence', {})
        # 证据中经常直接包含 'domain' 字段
        domain_val = evidence.get('domain', '')
        if isinstance(domain_val, str) and is_valid_domain(domain_val):
            domains.add(domain_val)
        elif isinstance(domain_val, list):
            for d in domain_val:
                if isinstance(d, str) and is_valid_domain(d):
                    domains.add(d)

        for _key, val in evidence.items():
            if isinstance(val, str):
                ips.update(_IP_PATTERN.findall(val))
                # 尝试从文本中提取域名
                found_domains = _DOMAIN_PATTERN.findall(val)
                for d in found_domains:
                    if is_valid_domain(d):
                        domains.add(d.lower())
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        ips.update(_IP_PATTERN.findall(item))
                        found_domains = _DOMAIN_PATTERN.findall(item)
                        for d in found_domains:
                            if is_valid_domain(d):
                                domains.add(d.lower())

        # 2. 从描述字段提取
        desc = threat.get('description', '')
        ips.update(_IP_PATTERN.findall(desc))
        found_domains = _DOMAIN_PATTERN.findall(desc)
        for d in found_domains:
            if is_valid_domain(d):
                domains.add(d.lower())

        # 3. 从 IOC 列表提取
        iocs = threat.get('ioc', [])
        for ioc in iocs:
            if _IP_PATTERN.match(ioc) and ioc.count('.') == 3:
                ips.add(ioc)
            elif is_valid_domain(ioc):
                domains.add(ioc.lower())

    return ips, domains


def _build_topology(df: pd.DataFrame, min_bytes: int = 1000, highlight_ips: set[str] | None = None, highlight_domains: set[str] | None = None) -> dict[str, Any]:
    if df is None or df.empty:
        return {"nodes": [], "links": []}

    # 1. 数据清洗：过滤无效 IP
    def is_valid_ip(ip_str):
        if pd.isna(ip_str):
            return False
        ip_str = str(ip_str).strip()
        if not ip_str:
            return False
        if ip_str in ('0.0.0.0', '255.255.255.255', '127.0.0.1'):
            return False
        if ip_str.endswith('.255'):
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_multicast or ip.is_link_local or ip.is_unspecified or ip.is_reserved)
        except ValueError:
            return False

    try:
        valid_src = df['src_ip'].apply(is_valid_ip)
        valid_dst = df['dst_ip'].apply(is_valid_ip)
        df_clean = df[valid_src & valid_dst]
    except Exception:
        return {"nodes": [], "links": []}

    if df_clean.empty:
        return {"nodes": [], "links": []}

    # 2. 聚合通信关系
    try:
        agg_df = df_clean.groupby(['src_ip', 'dst_ip']).agg(
            value=('bidirectional_bytes', 'sum'),
            label=('application_name', lambda x: ', '.join(filter(None, set(x.dropna().astype(str))))),
            sni=('requested_server_name', lambda x: list(filter(None, set(x.dropna().astype(str))))) # Collect SNI/Domains
        ).reset_index()
        agg_df['label'] = agg_df['label'].apply(lambda s: s[:30] if isinstance(s, str) else "")
        # Flatten SNI list to string for easier check
        agg_df['sni_str'] = agg_df['sni'].apply(lambda x: [str(s).lower() for s in x])
    except Exception:
        return {"nodes": [], "links": []}

    # 3. 过滤逻辑
    filtered_links = []

    # 如果提供了高亮 IP 或域名，仅保留涉及这些指标的流
    if highlight_ips or highlight_domains:
        for _, row in agg_df.iterrows():
            match_ip = False
            match_domain = False

            if highlight_ips and (row['src_ip'] in highlight_ips or row['dst_ip'] in highlight_ips):
                match_ip = True

            if highlight_domains:
                # 检查 SNI 是否包含目标域名
                for sni in row['sni_str']:
                    for target_domain in highlight_domains:
                        if sni == target_domain or sni.endswith('.' + target_domain):
                            match_domain = True
                            break
                    if match_domain:
                        break

            if match_ip or match_domain:
                filtered_links.append(row)

        if not filtered_links:
            return {"nodes": [], "links": []} # 没有命中目标

        agg_df = pd.DataFrame(filtered_links)

    # 全量模式：仅过滤小流量
    if not highlight_ips and not highlight_domains and min_bytes > 0:
        agg_df = agg_df[agg_df['value'] >= min_bytes]
        if agg_df.empty:
            return {"nodes": [], "links": []}

    links = []
    nodes_data = {} # Use dict to avoid duplicate nodes

    # 4. 生成连线 (Links) 和 节点 (Nodes)
    for row in agg_df.itertuples(index=False):
        src = str(row.src_ip)
        dst = str(row.dst_ip)
        val = int(row.value)
        label = str(row.label)
        sni_list = row.sni_str # List of domains associated with this flow

        # 收集 IP 节点
        if src not in nodes_data:
            nodes_data[src] = {'id': src, 'type': 'ip'}
        if dst not in nodes_data:
            nodes_data[dst] = {'id': dst, 'type': 'ip'}

        # 判断是否为高亮连线（威胁或异常）
        is_highlighted = False
        if highlight_ips and (src in highlight_ips or dst in highlight_ips):
            is_highlighted = True

        # 如果命中了域名，也算高亮
        if highlight_domains:
            for sni in sni_list:
                for domain in highlight_domains:
                    if sni == domain or sni.endswith('.' + domain):
                        is_highlighted = True
                        # 将域名加入节点，并建立连线 src -> domain
                        if domain not in nodes_data:
                            nodes_data[domain] = {'id': domain, 'type': 'domain'}
                        # 添加 IP -> Domain 连线
                        links.append({
                            "source": src,
                            "target": domain,
                            "value": val, # Use flow value
                            "label": "访问域名",
                            "isHighlighted": True,
                            "lineStyle": {
                                "width": 3.0,
                                "curveness": 0.3,
                                "color": "#ef4444",
                                "type": "dashed" # 虚线表示关联
                            }
                        })
                        break

        # 添加主 IP -> IP 连线
        links.append({
            "source": src,
            "target": dst,
            "value": val,
            "label": label,
            "isHighlighted": is_highlighted,
            "lineStyle": {
                "width": float(min(val / 1000000.0 + 1.0, 6.0)),
                "curveness": 0.2,
                "color": "#ef4444" if is_highlighted else "source"
            }
        })

    # 5. 构建最终节点列表
    nodes = []
    src_traffic = df_clean.groupby('src_ip')['bidirectional_bytes'].sum()
    dst_traffic = df_clean.groupby('dst_ip')['bidirectional_bytes'].sum()

    for item_id, item_info in nodes_data.items():
        if item_info['type'] == 'ip':
            t_src = int(src_traffic.get(item_id, 0))
            t_dst = int(dst_traffic.get(item_id, 0))
            traffic = max(t_src, t_dst)

            category = _get_ip_category(item_id)
            is_bad_actor = (highlight_ips and item_id in highlight_ips)

            # 如果该 IP 访问了高亮域名，也算异常
            if highlight_domains:
                # Check if this IP is connected to any highlighted domain
                for link in links:
                    if link.get('source') == item_id and link.get('isHighlighted') and link.get('target') in highlight_domains:
                        is_bad_actor = True
                        break

            color = _get_category_color(category)
            if is_bad_actor:
                category = "Threat Node"
                color = "#dc2626"

            nodes.append({
                "id": item_id,
                "name": item_id,
                "category": category,
                "symbolSize": float(min(max(traffic ** 0.35, 15.0), 70.0)),
                "draggable": True,
                "value": traffic,
                "itemStyle": {
                    "color": color,
                    "borderColor": "#fff",
                    "borderWidth": 2 if is_bad_actor else 1
                },
                "label": {
                    "show": traffic > 100000 or is_bad_actor,
                    "formatter": "{b}",
                    "fontSize": 11 if is_bad_actor else 10,
                    "color": "#ef4444" if is_bad_actor else "#e2e8f0"
                },
                "tooltip": {
                    "formatter": f"<b>{{b}}</b><br/>IP<br/>流量: {traffic/1024:.1f} KB"
                }
            })

        elif item_info['type'] == 'domain':
            # Domain node
            nodes.append({
                "id": item_id,
                "name": item_id,
                "category": "Domain",
                "symbolSize": 40,
                "draggable": True,
                "value": 0,
                "itemStyle": {
                    "color": "#f97316", # Orange for Domain
                    "borderColor": "#fff",
                    "borderWidth": 2
                },
                "label": {
                    "show": True,
                    "formatter": "{b}",
                    "fontSize": 11,
                    "color": "#f97316"
                },
                "tooltip": {
                    "formatter": "<b>{b}</b><br/>可疑域名"
                }
            })

    return {"nodes": nodes, "links": links}


def _get_ip_category(ip: str) -> str:
    """Categorize an IP address for visualization."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return "External Server"

    if ip_obj.is_private:
        # Check if it's a gateway (typically ends with .1 or .254)
        if ip.endswith('.1') or ip.endswith('.254'):
            return "Gateway/Router"
        return "Internal Host"
    elif ip in ('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '114.114.114.114'):
        return "Public DNS"
    return "External Server"


def _get_category_color(category: str) -> str:
    colors = {
        "Internal Host": "#4ea397",
        "External Server": "#e66c5e",
        "Public DNS": "#6d72c1",
        "Gateway/Router": "#f7bc8b",
        "Threat Node": "#dc2626",
        "Malicious IP": "#dc2626",
        "Domain": "#f97316"
    }
    return colors.get(category, "#73c0de")

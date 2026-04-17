"""
HTML Report Generator - 生成可视化 HTML 分析报告
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import AnalysisResult

logger = logging.getLogger(__name__)


class HTMLReportGenerator:
    """生成 HTML 分析报告，包含图表、可折叠告警、Top 10 威胁"""

    def __init__(self, result: AnalysisResult):
        self.result = result

    def generate(self, output_path: Optional[str] = None, api_stats: Optional[dict] = None) -> str:
        """生成完整 HTML 报告

        Args:
            output_path: 输出文件路径
            api_stats: API 使用统计 {'abuseipdb': {...}, 'threatbook': {...}}
        """
        self.api_stats = api_stats or {}
        html = self._build_html()
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info(f"HTML 报告已保存至: {output_path}")
        return html

    def _build_html(self) -> str:
        """构建完整 HTML"""
        threats = self.result.threats
        high_count = self.result.high_severity_count
        medium_count = self.result.medium_severity_count
        low_count = self.result.low_severity_count

        type_counts = {}
        for t in threats:
            t_type = t.threat_type.value
            type_counts[t_type] = type_counts.get(t_type, 0) + 1

        engine_counts = {}
        for t in threats:
            engine = getattr(t, 'engine_name', 'unknown')
            engine_counts[engine] = engine_counts.get(engine, 0) + 1

        top10 = threats[:10]
        all_alerts = threats
        proto_data = self.result.protocol_distribution or {}

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetflowSight 分析报告 - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --border: #334155;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --high: #ef4444;
            --medium: #f59e0b;
            --low: #22c55e;
            --accent: #3b82f6;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 30px;
        }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header .meta {{ color: var(--text-muted); font-size: 14px; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .value {{ font-size: 36px; font-weight: 700; margin-bottom: 4px; }}
        .stat-card .label {{ color: var(--text-muted); font-size: 14px; }}
        .stat-card.high .value {{ color: var(--high); }}
        .stat-card.medium .value {{ color: var(--medium); }}
        .stat-card.low .value {{ color: var(--low); }}
        .stat-card.info .value {{ color: var(--accent); }}
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .chart-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}
        .chart-card h3 {{ margin-bottom: 15px; font-size: 16px; }}
        .chart-container {{ position: relative; height: 300px; }}
        .section {{ margin-bottom: 30px; }}
        .section-title {{
            font-size: 20px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
        }}
        .threat-list {{ list-style: none; }}
        .threat-item {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 10px;
            overflow: hidden;
        }}
        .threat-header {{
            display: flex;
            align-items: center;
            padding: 14px 16px;
            cursor: pointer;
            user-select: none;
        }}
        .threat-header:hover {{ background: #263045; }}
        .threat-num {{
            width: 28px; height: 28px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 13px; font-weight: 600; margin-right: 12px; flex-shrink: 0;
        }}
        .threat-item.high .threat-num {{ background: var(--high); color: white; }}
        .threat-item.medium .threat-num {{ background: var(--medium); color: #000; }}
        .threat-item.low .threat-num {{ background: var(--low); color: #000; }}
        .threat-title {{ flex: 1; font-size: 14px; }}
        .threat-badge {{
            padding: 3px 10px; border-radius: 20px; font-size: 12px;
            font-weight: 500; margin-left: 10px;
        }}
        .badge-high {{ background: rgba(239,68,68,0.2); color: var(--high); }}
        .badge-medium {{ background: rgba(245,158,11,0.2); color: var(--medium); }}
        .badge-low {{ background: rgba(34,197,94,0.2); color: var(--low); }}
        .threat-arrow {{ margin-left: 10px; transition: transform 0.2s; color: var(--text-muted); }}
        .threat-item.open .threat-arrow {{ transform: rotate(180deg); }}
        .threat-detail {{
            display: none; padding: 0 16px 16px; font-size: 13px;
            color: var(--text-muted); border-top: 1px solid var(--border); padding-top: 12px;
        }}
        .threat-item.open .threat-detail {{ display: block; }}
        .detail-row {{ display: flex; margin-bottom: 6px; }}
        .detail-label {{ min-width: 80px; color: var(--text); font-weight: 500; }}
        .detail-value {{ word-break: break-all; }}
        .collapse-toggle {{
            background: var(--accent); color: white; border: none;
            padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; margin-bottom: 12px;
        }}
        .collapse-toggle:hover {{ background: #2563eb; }}
        .footer {{
            text-align: center; padding: 20px 0; border-top: 1px solid var(--border);
            color: var(--text-muted); font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NetflowSight 分析报告</h1>
            <div class="meta">
                生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
                PCAP 文件: {self.result.pcap_file} |
                处理耗时: {self.result.processing_time_ms:.0f} ms
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card info">
                <div class="value">{self.result.total_flows:,}</div>
                <div class="label">总流量数</div>
            </div>
            <div class="stat-card info">
                <div class="value">{self.result.total_packets:,}</div>
                <div class="label">总数据包数</div>
            </div>
            <div class="stat-card info">
                <div class="value">{self.result.total_bytes / 1e6:.2f} MB</div>
                <div class="label">总字节数</div>
            </div>
            <div class="stat-card high">
                <div class="value">{high_count}</div>
                <div class="label">高危威胁</div>
            </div>
            <div class="stat-card medium">
                <div class="value">{medium_count}</div>
                <div class="label">中危威胁</div>
            </div>
            <div class="stat-card low">
                <div class="value">{low_count}</div>
                <div class="label">低危威胁</div>
            </div>
        </div>

        {self._render_api_stats()}

        <div class="charts-grid">
            <div class="chart-card">
                <h3>📊 协议分布</h3>
                <div class="chart-container"><canvas id="protoChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>🚨 威胁类型分布</h3>
                <div class="chart-container"><canvas id="threatTypeChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>🔧 检测引擎分布</h3>
                <div class="chart-container"><canvas id="engineChart"></canvas></div>
            </div>
            <div class="chart-card">
                <h3>⚠️ 威胁严重程度</h3>
                <div class="chart-container"><canvas id="severityChart"></canvas></div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">🚨 Top 10 威胁</h2>
            <ul class="threat-list">{self._render_threat_list(top10)}</ul>
        </div>

        <div class="section">
            <h2 class="section-title">📋 全部告警 ({len(all_alerts)} 条)</h2>
            <button class="collapse-toggle" onclick="toggleAll(this)">展开/折叠全部</button>
            <ul class="threat-list">{self._render_threat_list(all_alerts)}</ul>
        </div>

        <div class="footer">由 NetflowSight 生成 - AI 驱动的网络流量分析平台</div>
    </div>

    <script>
        document.querySelectorAll('.threat-header').forEach(header => {{
            header.addEventListener('click', () => header.parentElement.classList.toggle('open'));
        }});
        function toggleAll(btn) {{
            const items = document.querySelectorAll('.threat-item');
            const allOpen = [...items].every(i => i.classList.contains('open'));
            items.forEach(i => allOpen ? i.classList.remove('open') : i.classList.add('open'));
        }}
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = '#334155';
        Chart.defaults.font.size = 12;
        new Chart(document.getElementById('protoChart'), {{
            type: 'doughnut',
            data: {{ labels: {json.dumps(list(proto_data.keys())[:10])}, datasets: [{{ data: {json.dumps(list(proto_data.values())[:10])}, backgroundColor: ['#3b82f6','#22c55e','#f59e0b','#ef4444','#8b5cf6','#ec4899','#06b6d4','#f97316','#14b8a6','#6366f1'] }}] }},
            options: {{ responsive: true, maintainAspectRatio: false }}
        }});
        new Chart(document.getElementById('threatTypeChart'), {{
            type: 'bar',
            data: {{ labels: {json.dumps(list(type_counts.keys()))}, datasets: [{{ label: '数量', data: {json.dumps(list(type_counts.values()))}, backgroundColor: '#3b82f6', borderRadius: 6 }}] }},
            options: {{ responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
        }});
        new Chart(document.getElementById('engineChart'), {{
            type: 'bar',
            data: {{ labels: {json.dumps(list(engine_counts.keys()))}, datasets: [{{ data: {json.dumps(list(engine_counts.values()))}, backgroundColor: ['#22c55e','#f59e0b','#ef4444','#8b5cf6','#06b6d4'], borderRadius: 6 }}] }},
            options: {{ indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: {{ legend: {{ display: false }} }}, scales: {{ x: {{ beginAtZero: true }} }} }}
        }});
        new Chart(document.getElementById('severityChart'), {{
            type: 'pie',
            data: {{ labels: ['高危', '中危', '低危'], datasets: [{{ data: [{high_count}, {medium_count}, {low_count}], backgroundColor: ['#ef4444', '#f59e0b', '#22c55e'] }}] }},
            options: {{ responsive: true, maintainAspectRatio: false }}
        }});
    </script>
</body>
</html>"""

    def _render_api_stats(self) -> str:
        """渲染 API 使用情况"""
        stats = self.api_stats
        if not stats:
            return ""
        abuseipdb = stats.get('abuseipdb', {})
        threatbook = stats.get('threatbook', {})
        cards = []
        if abuseipdb:
            cards.append(f"""
            <div class="stat-card info">
                <div class="value">{abuseipdb.get('api_queries', 0)}</div>
                <div class="label">AbuseIPDB API 查询</div>
            </div>
            <div class="stat-card info">
                <div class="value">{abuseipdb.get('cache_hits', 0)}</div>
                <div class="label">AbuseIPDB 缓存命中</div>
            </div>
            <div class="stat-card info">
                <div class="value">{abuseipdb.get('whitelist_size', 0)}</div>
                <div class="label">AbuseIPDB 白名单</div>
            </div>""")
        if threatbook:
            cards.append(f"""
            <div class="stat-card info">
                <div class="value">{threatbook.get('api_queries', 0)}</div>
                <div class="label">ThreatBook API 查询</div>
            </div>
            <div class="stat-card info">
                <div class="value">{threatbook.get('cache_hits', 0)}</div>
                <div class="label">ThreatBook 缓存命中</div>
            </div>
            <div class="stat-card info">
                <div class="value">{threatbook.get('whitelist_size', 0)}</div>
                <div class="label">ThreatBook 白名单</div>
            </div>""")
        return '<div class="stats-grid">' + '\n'.join(cards) + '</div>'

    def _render_threat_list(self, threats: list) -> str:
        """渲染威胁列表 HTML"""
        items = []
        for i, t in enumerate(threats, 1):
            sev = t.severity.value.lower()
            sev_label = {'high': '高危', 'medium': '中危', 'low': '低危'}.get(sev, sev.upper())
            badge_class = f'badge-{sev}'
            rec = getattr(t, 'recommended_action', None) or getattr(t, 'recommendation', '')
            evidence = getattr(t, 'evidence', {})
            iocs = getattr(t, 'ioc', [])
            detail_rows = ""
            if evidence:
                for k, v in evidence.items():
                    val = str(v)
                    if isinstance(v, list):
                        val = ', '.join(str(x) for x in v[:10])
                    detail_rows += f'<div class="detail-row"><span class="detail-label">{k}:</span><span class="detail-value">{val}</span></div>'
            if iocs:
                detail_rows += f'<div class="detail-row"><span class="detail-label">IOC:</span><span class="detail-value">{", ".join(str(x) for x in iocs)}</span></div>'
            if rec:
                detail_rows += f'<div class="detail-row"><span class="detail-label">建议:</span><span class="detail-value">{rec}</span></div>'
            items.append(f"""
            <li class="threat-item {sev}">
                <div class="threat-header">
                    <span class="threat-num">{i}</span>
                    <span class="threat-title">{t.description}</span>
                    <span class="threat-badge {badge_class}">{sev_label}</span>
                    <span class="threat-arrow">▼</span>
                </div>
                <div class="threat-detail">{detail_rows}</div>
            </li>""")
        return '\n'.join(items)

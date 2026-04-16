"""
外部插件目录

将自定义检测插件放在此目录，插件管理器会自动加载。

插件文件结构：
    my_plugin.py
    ├── get_plugin() -> BaseDetectionPlugin  # 必须导出
    └── MyPlugin(BaseDetectionPlugin)        # 插件实现

示例：
    def get_plugin():
        return MyPlugin(config={"threshold": 100})
"""

from pathlib import Path

# 此目录下的 .py 文件（非 _ 开头）将被自动加载
PLUGIN_DIR = Path(__file__).parent

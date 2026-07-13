"""dslsde — YAML 配置加载器

支持二进制级配置覆盖。
"""

import os
import yaml
from typing import Dict, Any, Optional

DEFAULT_CONFIG = {
    "engine": {
        "passes": 5,
        "ssa": True,
        "dce": True,
        "type_propagation": True,
    },
    "output": {
        "show_register_comments": False,
        "show_stack_canary": True,
        "indent_size": 2,
        "struct_field_naming": "field_n",  # field_n | offset | hex
    },
    "types": {
        "struct_min_fields": 2,
        "max_struct_size": 4096,
        "array_threshold": 3,
    },
    "signatures": {},  # 签名覆盖
    "structs": {},     # 预定义结构体
}

CONFIG_PATH = os.path.expanduser("~/.dslsde/config.yaml")


def load_config(path: Optional[str] = None) -> dict:
    """加载配置，合并默认值和用户覆盖"""
    config = DEFAULT_CONFIG.copy()

    load_path = path or CONFIG_PATH
    if os.path.exists(load_path):
        with open(load_path) as f:
            user_config = yaml.safe_load(f)
        if user_config:
            _deep_merge(config, user_config)

    return config


def _deep_merge(base: dict, override: dict):
    """递归合并字典"""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value

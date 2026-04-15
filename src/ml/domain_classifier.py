"""域名分类器模块 - 基于 LightGBM 的钓鱼/恶意域名检测"""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd
import lightgbm as lgb

logger = logging.getLogger(__name__)

_IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def extract_domain_features(domain: str) -> dict:
    """从域名字符串提取 ML 特征（共 15 个）"""
    domain = domain.lower().strip().rstrip(".")
    parts = domain.split(".")
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    tld = parts[-1] if len(parts) >= 1 else ""
    subdomain_count = max(0, len(parts) - 2)

    # 常见 TLD
    common_tlds = {
        "com", "cn", "net", "org", "de", "uk", "fr", "jp", "ru", "br",
        "it", "au", "in", "io", "dev", "app", "ai", "co", "me", "edu",
        "gov", "mil", "info", "biz", "name", "pro", "cc", "tv", "ws",
    }
    tld_is_common = 1 if tld in common_tlds else 0

    # 熵值计算
    if len(sld) > 0:
        sld_entropy = -sum((sld.count(c) / len(sld)) * math.log2(sld.count(c) / len(sld)) for c in set(sld))
    else:
        sld_entropy = 0.0

    digit_count = sum(1 for c in sld if c.isdigit())
    alpha_count = sum(1 for c in sld if c.isalpha())
    digit_ratio = digit_count / len(sld) if len(sld) > 0 else 0.0
    alpha_ratio = alpha_count / len(sld) if len(sld) > 0 else 0.0
    hyphen_count = sld.count("-")
    has_digit = 1 if digit_count > 0 else 0

    # 最大连续相同字符
    max_consecutive = 1
    cur = 1
    for i in range(1, len(sld)):
        if sld[i] == sld[i - 1]:
            cur += 1
            max_consecutive = max(max_consecutive, cur)
        else:
            cur = 1

    special_chars = sum(1 for c in domain if not c.isalnum() and c not in (".", "-"))
    special_char_ratio = special_chars / len(domain) if len(domain) > 0 else 0.0

    # 字母-数字转换频率
    transitions = 0
    for i in range(1, len(sld)):
        if (sld[i].isdigit() and sld[i - 1].isalpha()) or (sld[i].isalpha() and sld[i - 1].isdigit()):
            transitions += 1
    transition_ratio = transitions / len(sld) if len(sld) > 0 else 0.0

    vowels = set("aeiou")
    vowel_count = sum(1 for c in sld.lower() if c in vowels)
    vowel_ratio = vowel_count / len(sld) if len(sld) > 0 else 0.0
    is_ip = 1 if _IP_PATTERN.match(domain) else 0

    return {
        "domain_length": len(domain),
        "sld_length": len(sld),
        "tld_length": len(tld),
        "subdomain_count": subdomain_count,
        "tld_is_common": tld_is_common,
        "sld_entropy": sld_entropy,
        "digit_ratio": digit_ratio,
        "alpha_ratio": alpha_ratio,
        "hyphen_count": hyphen_count,
        "has_digit": has_digit,
        "max_consecutive": max_consecutive,
        "special_char_ratio": special_char_ratio,
        "transition_ratio": transition_ratio,
        "vowel_ratio": vowel_ratio,
        "is_ip": is_ip,
    }


FEATURE_NAMES = [
    "domain_length", "sld_length", "tld_length", "subdomain_count",
    "tld_is_common", "sld_entropy", "digit_ratio", "alpha_ratio",
    "hyphen_count", "has_digit", "max_consecutive", "special_char_ratio",
    "transition_ratio", "vowel_ratio", "is_ip",
]


class DomainClassifier:
    """基于 ML 的域名分类器，检测钓鱼和恶意域名"""

    def __init__(self, model_path: Optional[str] = None):
        self._model = None
        self._is_loaded = False

        if model_path is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            model_path = str(project_root / "models" / "domain_classifier_v1.pkl")

        self._model_path = model_path
        self._load_model()

    def _load_model(self) -> None:
        """加载预训练模型"""
        try:
            model_data = joblib.load(self._model_path)
            self._model = model_data["model"]
            self._is_loaded = True
            logger.info(f"域名分类器已加载 (AUC: {model_data.get('auc', 'unknown')})")
        except FileNotFoundError:
            logger.warning(f"域名分类器模型未找到: {self._model_path}，将使用规则检测")
            self._is_loaded = False
        except Exception as e:
            logger.warning(f"域名分类器模型加载失败: {e}")
            self._is_loaded = False

    def is_suspicious(self, domain: str, threshold: float = 0.5) -> tuple[bool, float]:
        """检测域名是否可疑"""
        if not self._is_loaded or self._model is None:
            return self._rule_based_check(domain)

        try:
            features = extract_domain_features(domain)
            feature_vec = pd.DataFrame([features])[FEATURE_NAMES]
            prob = self._model.predict_proba(feature_vec)[0, 1]
            return bool(prob >= threshold), float(prob)
        except Exception as e:
            logger.warning(f"域名分类失败 '{domain}': {e}")
            return False, 0.0

    def predict_batch(self, domains: list[str], threshold: float = 0.5) -> list[tuple[bool, float]]:
        """批量检测域名"""
        if not self._is_loaded or self._model is None:
            return [(self._rule_based_check(d)[0], 0.0) for d in domains]

        try:
            feature_list = []
            for domain in domains:
                features = extract_domain_features(domain)
                feature_list.append([features[f] for f in FEATURE_NAMES])

            X = pd.DataFrame(feature_list, columns=FEATURE_NAMES)
            probs = self._model.predict_proba(X)[:, 1]
            return [(bool(p >= threshold), float(p)) for p in probs]
        except Exception as e:
            logger.warning(f"批量域名分类失败: {e}")
            return [(False, 0.0) for _ in domains]

    def _rule_based_check(self, domain: str) -> tuple[bool, float]:
        """基于规则的域名检测（后备方案）"""
        domain = domain.lower().strip().rstrip(".")
        parts = domain.split(".")
        sld = parts[-2] if len(parts) >= 2 else parts[0]
        tld = parts[-1] if len(parts) >= 1 else ""

        suspicious_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz",
                           "club", "site", "online", "space", "work", "loan"}

        score = 0.0
        if tld in suspicious_tlds:
            score += 0.4
        if len(sld) > 25:
            score += 0.3
        if len(sld) > 10:
            entropy = -sum((sld.count(c) / len(sld)) * math.log2(sld.count(c) / len(sld)) for c in set(sld)) if len(sld) > 0 else 0
            if entropy > 3.5:
                score += 0.3
        if sld.count("-") > 2:
            score += 0.2

        return score >= 0.5, min(score, 1.0)

    @property
    def is_available(self) -> bool:
        """检查 ML 模型是否已加载"""
        return self._is_loaded

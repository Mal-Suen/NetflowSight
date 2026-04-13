"""
Domain Classifier for NetflowSight

ML-based domain classification using a model trained on the
PhiUSIIL Phishing URL Dataset (235K+ samples).

Replaces the hard-coded regex rules in smart_threat.py with
a data-driven approach for detecting suspicious domains.
"""

from __future__ import annotations

import logging
import math
import re
import time
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd
import lightgbm as lgb

logger = logging.getLogger(__name__)

# Precompiled regex
_IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def extract_domain_features(domain: str) -> dict:
    """
    Extract features from a domain string for ML classification.
    Must match the features used during training.
    """
    domain = domain.lower().strip().rstrip(".")

    parts = domain.split(".")
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    tld = parts[-1] if len(parts) >= 1 else ""
    subdomain_count = max(0, len(parts) - 2)

    common_tlds = {
        "com", "cn", "net", "org", "de", "uk", "fr", "jp", "ru", "br",
        "it", "au", "in", "io", "dev", "app", "ai", "co", "me", "edu",
        "gov", "mil", "info", "biz", "name", "pro", "cc", "tv", "ws",
        "mobi", "asia", "tel",
    }
    tld_is_common = 1 if tld in common_tlds else 0
    tld_length = len(tld)
    domain_length = len(domain)
    sld_length = len(sld)

    # SLD entropy
    if len(sld) > 0:
        sld_entropy = -sum(
            (sld.count(c) / len(sld)) * math.log2(sld.count(c) / len(sld))
            for c in set(sld)
        )
    else:
        sld_entropy = 0.0

    # Digit ratio
    digit_count = sum(1 for c in sld if c.isdigit())
    digit_ratio = digit_count / len(sld) if len(sld) > 0 else 0.0

    # Alpha ratio
    alpha_count = sum(1 for c in sld if c.isalpha())
    alpha_ratio = alpha_count / len(sld) if len(sld) > 0 else 0.0

    # Hyphen count
    hyphen_count = sld.count("-")
    has_digit = 1 if digit_count > 0 else 0

    # Max consecutive same char
    max_consecutive = 1
    cur = 1
    for i in range(1, len(sld)):
        if sld[i] == sld[i - 1]:
            cur += 1
            max_consecutive = max(max_consecutive, cur)
        else:
            cur = 1

    # Special char ratio
    special_chars = sum(1 for c in domain if not c.isalnum() and c not in (".", "-"))
    special_char_ratio = special_chars / len(domain) if len(domain) > 0 else 0.0

    # Transition ratio (alpha<->digit switching)
    transitions = 0
    for i in range(1, len(sld)):
        if (sld[i].isdigit() and sld[i - 1].isalpha()) or \
           (sld[i].isalpha() and sld[i - 1].isdigit()):
            transitions += 1
    transition_ratio = transitions / len(sld) if len(sld) > 0 else 0.0

    # Vowel ratio
    vowels = set("aeiou")
    vowel_count = sum(1 for c in sld.lower() if c in vowels)
    vowel_ratio = vowel_count / len(sld) if len(sld) > 0 else 0.0

    is_ip = 1 if _IP_PATTERN.match(domain) else 0

    return {
        "domain_length": domain_length,
        "sld_length": sld_length,
        "tld_length": tld_length,
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
    """
    ML-based domain classifier for phishing/malicious domain detection.

    Trained on the PhiUSIIL Phishing URL Dataset (235,795 samples).
    Achieves 87% accuracy, 94% precision on malicious domains,
    and ROC-AUC of 0.903.

    Usage:
        classifier = DomainClassifier()
        is_malicious, probability = classifier.is_suspicious("evil-site.tk")
    """

    def __init__(self, model_path: Optional[str] = None):
        self._model = None
        self._is_loaded = False

        # Default model path
        if model_path is None:
            # Try project root /models/ first (where training script saves to)
            project_root = Path(__file__).resolve().parent.parent.parent
            model_path = str(project_root / "models" / "domain_classifier_v1.pkl")

        self._model_path = model_path
        self._load_model()

    def _load_model(self) -> None:
        """Load the trained domain classifier model."""
        try:
            model_data = joblib.load(self._model_path)
            self._model = model_data["model"]
            self._is_loaded = True
            logger.info(
                f"Domain classifier loaded (AUC: {model_data.get('auc', 'unknown')})"
            )
        except FileNotFoundError:
            logger.warning(
                f"Domain classifier model not found at {self._model_path}. "
                "Falling back to rule-based detection."
            )
            self._is_loaded = False
        except Exception as e:
            logger.warning(f"Failed to load domain classifier model: {e}")
            self._is_loaded = False

    def is_suspicious(self, domain: str, threshold: float = 0.5) -> tuple[bool, float]:
        """
        Check if a domain is suspicious using the ML model.

        Args:
            domain: Domain string to check
            threshold: Probability threshold for classification (default 0.5)

        Returns:
            (is_suspicious, malicious_probability)
        """
        if not self._is_loaded or self._model is None:
            # Fallback: basic heuristic when model unavailable
            return self._rule_based_check(domain)

        try:
            features = extract_domain_features(domain)
            feature_vec = pd.DataFrame([features])[FEATURE_NAMES]
            prob = self._model.predict_proba(feature_vec)[0, 1]
            return bool(prob >= threshold), float(prob)
        except Exception as e:
            logger.warning(f"Domain classification failed for '{domain}': {e}")
            return False, 0.0

    def predict_batch(self, domains: list[str], threshold: float = 0.5) -> list[tuple[bool, float]]:
        """
        Batch predict suspicious domains.

        Args:
            domains: List of domains to check
            threshold: Probability threshold

        Returns:
            List of (is_suspicious, probability) tuples
        """
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
            logger.warning(f"Batch domain classification failed: {e}")
            return [(False, 0.0) for _ in domains]

    def _rule_based_check(self, domain: str) -> tuple[bool, float]:
        """Fallback rule-based check when model is unavailable."""
        domain = domain.lower().strip().rstrip(".")
        parts = domain.split(".")
        sld = parts[-2] if len(parts) >= 2 else parts[0]
        tld = parts[-1] if len(parts) >= 1 else ""

        suspicious_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz",
                           "club", "site", "online", "space", "work", "loan",
                           "win", "stream", "download", "account", "verify",
                           "secure", "login", "click", "update"}

        score = 0.0
        if tld in suspicious_tlds:
            score += 0.4
        if len(sld) > 25:
            score += 0.3
        if len(sld) > 10:
            # Entropy check
            entropy = -sum(
                (sld.count(c) / len(sld)) * math.log2(sld.count(c) / len(sld))
                for c in set(sld)
            ) if len(sld) > 0 else 0
            if entropy > 3.5:
                score += 0.3
        if sld.count("-") > 2:
            score += 0.2

        return score >= 0.5, min(score, 1.0)

    @property
    def is_available(self) -> bool:
        """Check if the ML model is loaded."""
        return self._is_loaded

"""
域名分类模型训练脚本

从 PhiUSIIL Phishing URL 数据集中提取域名结构特征，
训练轻量级域名分类模型，替代 smart_threat.py 的硬编码正则规则。

用法:
    python scripts/train_domain_classifier.py
"""

import math
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import lightgbm as lgb

_IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
COMMON_TLDS = {
    "com", "cn", "net", "org", "de", "uk", "fr", "jp", "ru", "br",
    "it", "au", "in", "io", "dev", "app", "ai", "co", "me", "edu",
    "gov", "mil", "info", "biz", "name", "pro", "cc", "tv", "ws",
    "mobi", "asia", "tel",
}
FEATURE_NAMES = [
    "domain_length", "sld_length", "tld_length", "subdomain_count",
    "tld_is_common", "sld_entropy", "digit_ratio", "alpha_ratio",
    "hyphen_count", "has_digit", "max_consecutive", "special_char_ratio",
    "transition_ratio", "vowel_ratio", "is_ip",
]


def extract_domain_features(domain: str) -> dict:
    domain = domain.lower().strip().rstrip(".")
    parts = domain.split(".")
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    tld = parts[-1] if len(parts) >= 1 else ""
    subdomain_count = max(0, len(parts) - 2)
    tld_is_common = 1 if tld in COMMON_TLDS else 0

    if len(sld) > 0:
        sld_entropy = -sum((sld.count(c)/len(sld))*math.log2(sld.count(c)/len(sld)) for c in set(sld))
    else:
        sld_entropy = 0.0

    digit_count = sum(1 for c in sld if c.isdigit())
    alpha_count = sum(1 for c in sld if c.isalpha())
    sld_len = len(sld)
    max_consecutive = 1; cur = 1
    for i in range(1, sld_len):
        if sld[i] == sld[i-1]: cur += 1; max_consecutive = max(max_consecutive, cur)
        else: cur = 1
    special_chars = sum(1 for c in domain if not c.isalnum() and c not in (".", "-"))
    transitions = sum(1 for i in range(1, sld_len) if (sld[i].isdigit() != sld[i-1].isdigit()))
    vowel_count = sum(1 for c in sld.lower() if c in "aeiou")

    return {
        "domain_length": len(domain), "sld_length": sld_len,
        "tld_length": len(tld), "subdomain_count": subdomain_count,
        "tld_is_common": tld_is_common, "sld_entropy": sld_entropy,
        "digit_ratio": digit_count/sld_len if sld_len else 0,
        "alpha_ratio": alpha_count/sld_len if sld_len else 0,
        "hyphen_count": sld.count("-"), "has_digit": 1 if digit_count else 0,
        "max_consecutive": max_consecutive,
        "special_char_ratio": special_chars/len(domain) if domain else 0,
        "transition_ratio": transitions/sld_len if sld_len else 0,
        "vowel_ratio": vowel_count/sld_len if sld_len else 0,
        "is_ip": 1 if _IP_PATTERN.match(domain) else 0,
    }


def main():
    print("=" * 60)
    print("NetflowSight 域名分类模型训练")
    print("=" * 60)

    dataset_path = Path(r"E:\PycharmProjects\Malicious-Website-Detection\data\PhiUSIIL_Phishing_URL_Dataset.csv")
    if not dataset_path.exists():
        print(f"错误: 数据集不存在: {dataset_path}"); sys.exit(1)

    print(f"\n加载数据集...")
    df = pd.read_csv(dataset_path, usecols=["Domain", "label"])
    df["is_malicious"] = (df["label"] == 0).astype(int)
    print(f"  正常: {(df['is_malicious']==0).sum():,} | 恶意: {(df['is_malicious']==1).sum():,}")

    print("\n提取特征...")
    features = df["Domain"].apply(extract_domain_features).apply(pd.Series)
    X = features[FEATURE_NAMES].fillna(0)
    y = df["is_malicious"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"  训练集: {len(X_train):,} | 测试集: {len(X_test):,}")

    print("\n训练 LightGBM 分类器...")
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("lgbm", lgb.LGBMClassifier(n_estimators=200, max_depth=8, learning_rate=0.05,
                                     num_leaves=31, random_state=42, n_jobs=-1, verbose=-1))
    ])
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print(f"\nAUC: {auc:.4f} | 准确率: {(tp+tn)/(tp+tn+fp+fn):.4f} | FP: {fp} | FN: {fn}")
    print(f"\n特征重要性 (Top 5):")
    for name, imp in sorted(zip(FEATURE_NAMES, model.named_steps["lgbm"].feature_importances_),
                            key=lambda x: -x[1])[:5]:
        print(f"  {name}: {imp:.0f}")

    output_dir = Path(__file__).resolve().parent.parent / "models"
    output_dir.mkdir(parents=True, exist_ok=True)
    model_data = {"model": model, "feature_names": FEATURE_NAMES, "version": "1.0.0", "auc": round(auc, 4)}
    model_path = output_dir / "domain_classifier_v1.pkl"
    joblib.dump(model_data, model_path, compress=3)
    print(f"\n模型已保存: {model_path} ({model_path.stat().st_size / 1024:.0f} KB)")

    feature_file = output_dir / "domain_features.txt"
    feature_file.write_text("\n".join(FEATURE_NAMES))
    print("训练完成!")


if __name__ == "__main__":
    main()

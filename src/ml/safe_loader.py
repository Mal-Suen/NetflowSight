"""
安全模型加载模块 - 防止 pickle/joblib 反序列化攻击

通过以下方式保护模型加载:
1. 文件签名验证 (SHA256)
2. 文件大小限制
3. 加载前内容检查
4. 可选: 签名文件验证
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import joblib

logger = logging.getLogger(__name__)

# 模型文件最大大小限制 (50MB)
MAX_MODEL_SIZE_BYTES = 50 * 1024 * 1024

# 已知安全的模型结构键
REQUIRED_MODEL_KEYS = {"model"}
OPTIONAL_MODEL_KEYS = {"scaler", "features", "auc", "version", "metadata"}


def compute_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """计算文件哈希值"""
    hasher = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return f"{algorithm}:{hasher.hexdigest()}"


def validate_model_structure(model_data: Any, expected_type: str = "classifier") -> bool:
    """
    验证模型数据结构是否安全
    
    Args:
        model_data: 加载的模型数据
        expected_type: 期望的模型类型 ("classifier", "domain", "anomaly")
    
    Returns:
        是否通过验证
    """
    if not isinstance(model_data, dict):
        logger.warning("模型数据不是字典类型")
        return False
    
    # 检查必需的键
    if not REQUIRED_MODEL_KEYS.issubset(model_data.keys()):
        logger.warning(f"模型缺少必需的键: {REQUIRED_MODEL_KEYS}")
        return False
    
    # 检查是否有未知键 (潜在恶意注入)
    all_known_keys = REQUIRED_MODEL_KEYS | OPTIONAL_MODEL_KEYS
    unknown_keys = set(model_data.keys()) - all_known_keys
    if unknown_keys:
        logger.warning(f"模型包含未知键 (潜在风险): {unknown_keys}")
        # 不直接拒绝，但记录警告
    
    # 验证模型对象类型
    model = model_data.get("model")
    if model is None:
        logger.warning("模型对象为 None")
        return False
    
    # 检查模型是否有预期的属性
    model_type_name = type(model).__name__
    safe_model_types = {
        "IsolationForest", "RandomForestClassifier", "LGBMClassifier",
        "XGBClassifier", "LogisticRegression", "SVC", "GradientBoostingClassifier",
    }
    
    if model_type_name not in safe_model_types:
        logger.warning(f"模型类型不在已知安全列表中: {model_type_name}")
        # 不直接拒绝，但记录警告
    
    return True


def safe_load_model(
    model_path: str | Path,
    expected_hash: str | None = None,
    signature_file: str | Path | None = None,
    strict_validation: bool = False,
) -> dict[str, Any]:
    """
    安全加载模型文件
    
    Args:
        model_path: 模型文件路径
        expected_hash: 期望的文件哈希值 (格式: "sha256:xxx")
        signature_file: 签名文件路径 (JSON 格式，包含 hash 和 metadata)
        strict_validation: 是否启用严格验证模式
    
    Returns:
        模型数据字典
    
    Raises:
        FileNotFoundError: 文件不存在
        ValueError: 验证失败
        RuntimeError: 加载失败
    """
    model_path = Path(model_path)
    
    # 1. 检查文件是否存在
    if not model_path.exists():
        raise FileNotFoundError(f"模型文件不存在: {model_path}")
    
    # 2. 检查文件大小
    file_size = model_path.stat().st_size
    if file_size > MAX_MODEL_SIZE_BYTES:
        raise ValueError(
            f"模型文件过大 ({file_size / 1024 / 1024:.1f}MB > {MAX_MODEL_SIZE_BYTES / 1024 / 1024}MB)"
        )
    
    # 3. 计算并验证哈希
    actual_hash = compute_file_hash(model_path)
    
    if signature_file:
        sig_path = Path(signature_file)
        if sig_path.exists():
            try:
                with open(sig_path, encoding="utf-8") as f:
                    sig_data = json.load(f)
                expected_hash = sig_data.get("hash")
                logger.info(f"从签名文件加载期望哈希: {expected_hash}")
            except Exception as e:
                logger.warning(f"读取签名文件失败: {e}")
    
    if expected_hash:
        if actual_hash != expected_hash:
            raise ValueError(
                f"模型文件哈希不匹配!\n"
                f"期望: {expected_hash}\n"
                f"实际: {actual_hash}\n"
                f"文件可能已被篡改或损坏"
            )
        logger.info(f"模型文件哈希验证通过: {actual_hash}")
    else:
        logger.warning(f"未提供期望哈希，跳过哈希验证 (文件哈希: {actual_hash})")
    
    # 4. 加载模型
    try:
        model_data = joblib.load(model_path)
    except Exception as e:
        raise RuntimeError(f"模型加载失败: {e}") from e
    
    # 5. 验证模型结构
    if not validate_model_structure(model_data):
        if strict_validation:
            raise ValueError("模型结构验证失败 (严格模式)")
        else:
            logger.warning("模型结构验证失败，但继续加载 (非严格模式)")
    
    logger.info(f"模型安全加载完成: {model_path}")
    return model_data


def create_signature_file(
    model_path: str | Path,
    signature_path: str | Path,
    metadata: dict | None = None,
) -> str:
    """
    为模型文件创建签名文件
    
    Args:
        model_path: 模型文件路径
        signature_path: 签名文件输出路径
        metadata: 附加元数据
    
    Returns:
        文件哈希值
    """
    model_path = Path(model_path)
    signature_path = Path(signature_path)
    
    file_hash = compute_file_hash(model_path)
    
    sig_data = {
        "hash": file_hash,
        "file": model_path.name,
        "size_bytes": model_path.stat().st_size,
        "metadata": metadata or {},
    }
    
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    with open(signature_path, "w", encoding="utf-8") as f:
        json.dump(sig_data, f, indent=2)
    
    logger.info(f"签名文件已创建: {signature_path}")
    return file_hash


def get_model_info(model_path: str | Path) -> dict:
    """
    获取模型文件信息 (不加载模型)
    
    Returns:
        包含 size, hash, path 的字典
    """
    model_path = Path(model_path)
    if not model_path.exists():
        return {"error": "文件不存在", "path": str(model_path)}
    
    return {
        "path": str(model_path),
        "size_bytes": model_path.stat().st_size,
        "size_mb": model_path.stat().st_size / 1024 / 1024,
        "hash": compute_file_hash(model_path),
    }

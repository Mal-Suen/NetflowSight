"""Tests for safe model loader"""

import json
import tempfile
from pathlib import Path

import pytest
from sklearn.ensemble import IsolationForest

from ml.safe_loader import (
    compute_file_hash,
    create_signature_file,
    get_model_info,
    safe_load_model,
    validate_model_structure,
)


@pytest.fixture
def valid_model_file():
    """创建一个有效的模型文件"""
    import joblib
    
    model = IsolationForest(n_estimators=10, random_state=42)
    model.fit([[1, 2], [3, 4], [5, 6]])
    
    model_data = {
        "model": model,
        "features": ["feature1", "feature2"],
        "auc": 0.85,
    }
    
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        joblib.dump(model_data, f)
        yield f.name
    
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def invalid_model_file():
    """创建一个无效结构的模型文件"""
    import joblib
    
    # 缺少 model 键
    model_data = {"features": ["a", "b"]}
    
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        joblib.dump(model_data, f)
        yield f.name
    
    Path(f.name).unlink(missing_ok=True)


class TestSafeLoader:
    def test_compute_file_hash(self, valid_model_file):
        """测试文件哈希计算"""
        hash_result = compute_file_hash(valid_model_file)
        assert hash_result.startswith("sha256:")
        assert len(hash_result) == 71  # "sha256:" + 64 hex chars
    
    def test_compute_file_hash_consistency(self, valid_model_file):
        """测试哈希一致性"""
        hash1 = compute_file_hash(valid_model_file)
        hash2 = compute_file_hash(valid_model_file)
        assert hash1 == hash2
    
    def test_validate_model_structure_valid(self, valid_model_file):
        """测试有效模型结构验证"""
        import joblib
        model_data = joblib.load(valid_model_file)
        assert validate_model_structure(model_data) is True
    
    def test_validate_model_structure_invalid(self, invalid_model_file):
        """测试无效模型结构验证"""
        import joblib
        model_data = joblib.load(invalid_model_file)
        assert validate_model_structure(model_data) is False
    
    def test_validate_model_structure_non_dict(self):
        """测试非字典模型数据"""
        assert validate_model_structure("not a dict") is False
        assert validate_model_structure(None) is False
        assert validate_model_structure([1, 2, 3]) is False
    
    def test_safe_load_model_basic(self, valid_model_file):
        """测试基本安全加载"""
        model_data = safe_load_model(valid_model_file)
        assert "model" in model_data
        assert model_data["model"] is not None
    
    def test_safe_load_model_with_hash_verification(self, valid_model_file):
        """测试带哈希验证的加载"""
        # 先计算正确的哈希
        correct_hash = compute_file_hash(valid_model_file)
        
        model_data = safe_load_model(valid_model_file, expected_hash=correct_hash)
        assert "model" in model_data
    
    def test_safe_load_model_wrong_hash(self, valid_model_file):
        """测试哈希不匹配时抛出异常"""
        wrong_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        
        with pytest.raises(ValueError, match="哈希不匹配"):
            safe_load_model(valid_model_file, expected_hash=wrong_hash)
    
    def test_safe_load_model_nonexistent_file(self):
        """测试加载不存在的文件"""
        with pytest.raises(FileNotFoundError):
            safe_load_model("/nonexistent/path/model.pkl")
    
    def test_safe_load_model_strict_validation(self, invalid_model_file):
        """测试严格验证模式"""
        with pytest.raises(ValueError, match="验证失败"):
            safe_load_model(invalid_model_file, strict_validation=True)
    
    def test_create_signature_file(self, valid_model_file):
        """测试创建签名文件"""
        with tempfile.TemporaryDirectory() as tmpdir:
            sig_path = Path(tmpdir) / "model.sig.json"
            
            file_hash = create_signature_file(
                valid_model_file,
                str(sig_path),
                metadata={"version": "1.0"},
            )
            
            assert file_hash.startswith("sha256:")
            assert sig_path.exists()
            
            # 验证签名文件内容
            with open(sig_path) as f:
                sig_data = json.load(f)
            
            assert sig_data["hash"] == file_hash
            assert "size_bytes" in sig_data
            assert sig_data["metadata"]["version"] == "1.0"
    
    def test_safe_load_with_signature_file(self, valid_model_file):
        """测试使用签名文件加载"""
        with tempfile.TemporaryDirectory() as tmpdir:
            sig_path = Path(tmpdir) / "model.sig.json"
            
            # 创建签名文件
            create_signature_file(valid_model_file, str(sig_path))
            
            # 使用签名文件加载
            model_data = safe_load_model(valid_model_file, signature_file=str(sig_path))
            assert "model" in model_data
    
    def test_get_model_info(self, valid_model_file):
        """测试获取模型信息"""
        info = get_model_info(valid_model_file)
        
        assert "path" in info
        assert "size_bytes" in info
        assert "size_mb" in info
        assert "hash" in info
        assert info["hash"].startswith("sha256:")
    
    def test_get_model_info_nonexistent(self):
        """测试获取不存在文件的信息"""
        info = get_model_info("/nonexistent/model.pkl")
        assert "error" in info
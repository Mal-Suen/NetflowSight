"""Tests for ML-based domain classifier"""

from ml.domain_classifier import FEATURE_NAMES, DomainClassifier, extract_domain_features


class TestExtractDomainFeatures:
    def test_normal_domain_features(self):
        features = extract_domain_features("www.google.com")
        assert features["domain_length"] == len("www.google.com")
        assert features["tld_is_common"] == 1
        assert features["subdomain_count"] == 1
        assert features["is_ip"] == 0

    def test_phishing_domain_features(self):
        features = extract_domain_features("x7k2m9q4.tk")
        assert features["tld_is_common"] == 0
        assert features["sld_length"] == 8
        assert features["digit_ratio"] >= 0.5

    def test_ip_address(self):
        features = extract_domain_features("192.168.1.1")
        assert features["is_ip"] == 1

    def test_empty_domain(self):
        features = extract_domain_features("")
        assert features["domain_length"] == 0
        assert features["sld_entropy"] == 0.0

    def test_dga_like_domain(self):
        features = extract_domain_features("xkqz7w3m9vbn2.net")
        assert features["sld_entropy"] > 3.0
        assert features["sld_length"] > 10

    def test_feature_names_match(self):
        features = extract_domain_features("test.example.com")
        assert set(features.keys()) == set(FEATURE_NAMES)


class TestDomainClassifierIntegration:
    def test_classifier_instantiates(self):
        c = DomainClassifier()
        assert isinstance(c.is_available, bool)

    def test_model_file_exists(self):
        from pathlib import Path
        project_root = Path(__file__).resolve().parent.parent
        model_path = project_root / "models" / "domain_classifier_v1.pkl"
        assert model_path.exists(), f"Model not found at {model_path}"

    def test_feature_count(self):
        assert len(FEATURE_NAMES) == 15

    def test_feature_names_order(self):
        expected = [
            "domain_length", "sld_length", "tld_length", "subdomain_count",
            "tld_is_common", "sld_entropy", "digit_ratio", "alpha_ratio",
            "hyphen_count", "has_digit", "max_consecutive", "special_char_ratio",
            "transition_ratio", "vowel_ratio", "is_ip",
        ]
        assert expected == FEATURE_NAMES

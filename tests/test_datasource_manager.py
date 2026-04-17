"""Tests for DataSourceManager"""

import json
from pathlib import Path

import pytest

from datasource.manager import DataSource, DataSourceCategory, DataSourceManager, DataSourceType


@pytest.fixture
def temp_data_dir(tmp_path):
    return str(tmp_path / "data")


@pytest.fixture
def manager(temp_data_dir):
    return DataSourceManager(data_dir=temp_data_dir, auto_load_state=False,
                             auto_update_on_start=False, interactive=False)


class TestDataSourceManagerInit:
    def test_default_sources_registered(self, manager):
        sources = manager.list_sources()
        assert len(sources) > 0
        names = [s["name"] for s in sources]
        assert "builtin_safe_domains" in names

    def test_data_dir_created(self, tmp_path):
        data_dir = str(tmp_path / "data")
        DataSourceManager(data_dir=data_dir, auto_load_state=False,
                          auto_update_on_start=False, interactive=False)
        assert Path(data_dir).exists()


class TestDataSourceLookup:
    def test_whitelist_exact_match(self, manager):
        assert manager.lookup(DataSourceCategory.WHITELIST_DOMAINS, "google.com") is True

    def test_whitelist_subdomain_match(self, manager):
        assert manager.lookup(DataSourceCategory.WHITELIST_DOMAINS, "mail.google.com") is True

    def test_whitelist_no_substring_match(self, manager):
        assert manager.lookup(DataSourceCategory.WHITELIST_DOMAINS, "evil-api.malware.com") is False

    def test_suspicious_ua_substring_match(self, manager):
        assert manager.lookup(DataSourceCategory.SUSPICIOUS_UA, "python-requests/2.28") is True

    def test_phishing_keyword_substring_match(self, manager):
        assert manager.lookup(DataSourceCategory.PHISHING_KEYWORDS, "account-verify") is True

    def test_whitelist_not_in_combined(self, manager):
        assert manager.lookup(DataSourceCategory.WHITELIST_DOMAINS, "totally-random-evil-site.xyz") is False


class TestDataSourceAddRemove:
    def test_add_source(self, manager):
        manager.add_source(DataSource(name="test_source", category=DataSourceCategory.THREAT_IPS,
                                       source_type=DataSourceType.LOCAL_FILE, url_or_path="test.txt",
                                       items={"1.2.3.4"}))
        names = [s["name"] for s in manager.list_sources()]
        assert "test_source" in names

    def test_remove_source(self, manager):
        assert manager.remove_source("builtin_safe_domains") is True
        names = [s["name"] for s in manager.list_sources()]
        assert "builtin_safe_domains" not in names

    def test_enable_disable_source(self, manager):
        assert manager.disable_source("builtin_safe_domains") is True
        assert manager.get_source("builtin_safe_domains").enabled is False
        assert manager.enable_source("builtin_safe_domains") is True


class TestDataSourceState:
    def test_save_and_load_state(self, manager, temp_data_dir):
        manager.save_state()
        state_path = Path(temp_data_dir) / "state.json"
        assert state_path.exists()
        with open(state_path) as f:
            state = json.load(f)
        assert "sources" in state

    def test_load_nonexistent_state(self, manager):
        assert manager.load_state("/nonexistent/path") is False


class TestDataSourceGetItems:
    def test_get_safe_domains(self, manager):
        domains = manager.get_items(DataSourceCategory.WHITELIST_DOMAINS)
        assert len(domains) > 0
        assert "google.com" in domains

    def test_get_items_returns_copy(self, manager):
        domains = manager.get_items(DataSourceCategory.WHITELIST_DOMAINS)
        domains.add("evil.com")
        domains2 = manager.get_items(DataSourceCategory.WHITELIST_DOMAINS)
        assert "evil.com" not in domains2

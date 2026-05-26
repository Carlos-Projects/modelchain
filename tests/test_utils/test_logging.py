from __future__ import annotations

from modelchain.utils.logging import get_logger


class TestLogging:
    def test_get_logger(self):
        log = get_logger("test-modelchain")
        assert log is not None
        assert log.name == "test-modelchain"

    def test_get_logger_singleton(self):
        log1 = get_logger("modelchain")
        log2 = get_logger("modelchain")
        assert log1 is log2

    def test_logger_level(self):
        log = get_logger("test-level")
        assert log.level > 0

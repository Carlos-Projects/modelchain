from __future__ import annotations

from modelchain.supply_chain.osv_client import OSVClient


class TestOSVClient:
    def test_cvss_to_severity_critical(self):
        assert OSVClient._cvss_to_severity(9.0) == "CRITICAL"
        assert OSVClient._cvss_to_severity(10.0) == "CRITICAL"

    def test_cvss_to_severity_high(self):
        assert OSVClient._cvss_to_severity(7.0) == "HIGH"
        assert OSVClient._cvss_to_severity(8.9) == "HIGH"

    def test_cvss_to_severity_medium(self):
        assert OSVClient._cvss_to_severity(4.0) == "MEDIUM"
        assert OSVClient._cvss_to_severity(6.9) == "MEDIUM"

    def test_cvss_to_severity_low(self):
        assert OSVClient._cvss_to_severity(0.0) == "LOW"
        assert OSVClient._cvss_to_severity(3.9) == "LOW"

    def test_parse_response_empty(self):
        client = OSVClient()
        result = client._parse_response({}, "test-pkg", "1.0")
        assert result == []

    def test_close_idempotent(self):
        client = OSVClient()
        client.close()
        client.close()

    def test_context_manager(self):
        with OSVClient() as client:
            assert client is not None

from __future__ import annotations

from modelchain.sbom.validator import SBOMValidator


class TestSBOMValidator:
    def test_validate_modelchain_valid(self):
        validator = SBOMValidator()
        sbom = {
            "modelchain": {"format": "modelchain"},
            "model": {"name": "test", "version": "1.0"},
            "datasets": [],
            "adapters": [],
            "dependencies": [],
        }
        errors = validator.validate_modelchain(sbom)
        assert errors == []

    def test_validate_modelchain_missing_sections(self):
        validator = SBOMValidator()
        errors = validator.validate_modelchain({})
        assert "Missing modelchain wrapper" in errors
        assert "Missing model section" in errors

    def test_validate_cyclonedx_valid(self):
        validator = SBOMValidator()
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:1234",
            "components": [{"name": "test", "type": "application"}],
        }
        errors = validator.validate_cyclonedx(sbom)
        assert errors == []

    def test_validate_cyclonedx_missing_fields(self):
        validator = SBOMValidator()
        errors = validator.validate_cyclonedx({})
        assert "Missing or invalid bomFormat" in errors
        assert "Missing serialNumber" in errors

    def test_validate_spdx_valid(self):
        validator = SBOMValidator()
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"created": "2026-01-01T00:00:00Z"},
            "packages": [{"SPDXID": "SPDXRef-Pkg", "name": "test"}],
        }
        errors = validator.validate_spdx(sbom)
        assert errors == []

    def test_validate_spdx_missing_fields(self):
        validator = SBOMValidator()
        errors = validator.validate_spdx({})
        assert "Missing or invalid spdxVersion" in errors
        assert "Missing dataLicense" in errors

    def test_validate_unknown_format(self):
        validator = SBOMValidator()
        errors = validator.validate({}, "invalid")
        assert len(errors) == 1
        assert "Unknown format" in errors[0]

    def test_validate_dispatches_correctly(self):
        validator = SBOMValidator()
        for fmt in ["modelchain", "cyclonedx", "spdx"]:
            errors = validator.validate({}, fmt)
            assert len(errors) >= 1  # all empty dicts fail validation

class TestSBOMValidatorDetailed:
    def test_validate_cyclonedx_missing_bomformat(self):
        validator = SBOMValidator()
        errors = validator.validate_cyclonedx({})
        # Check first error
        assert any("bomFormat" in e for e in errors)
        assert any("serialNumber" in e for e in errors)

    def test_validate_spdx_missing_spdx_version(self):
        validator = SBOMValidator()
        errors = validator.validate_spdx({})
        assert any("spdxVersion" in e for e in errors)
        assert any("dataLicense" in e for e in errors)

    def test_validate_modelchain_invalid_format(self):
        validator = SBOMValidator()
        errors = validator.validate_modelchain({"modelchain": {"format": "invalid"}})
        assert len(errors) > 0

from __future__ import annotations

from typing import Any


class SBOMValidator:
    """Validates SBOM output against expected schemas.

    Checks structural correctness of CycloneDX 1.6, SPDX 2.3,
    and ModelChain native format SBOMs.
    """

    def validate_cyclonedx(self, sbom: dict[str, Any]) -> list[str]:
        """Validate a CycloneDX SBOM document.

        Args:
            sbom: CycloneDX document dict.

        Returns:
            List of validation errors (empty = valid).
        """
        errors: list[str] = []

        if sbom.get("bomFormat") != "CycloneDX":
            errors.append("Missing or invalid bomFormat")

        spec = sbom.get("specVersion", "")
        if not spec.startswith("1."):
            errors.append(f"Missing or invalid specVersion: {spec}")

        if "serialNumber" not in sbom:
            errors.append("Missing serialNumber")

        if "components" not in sbom:
            errors.append("Missing components list")
        elif not isinstance(sbom["components"], list):
            errors.append("components must be a list")
        else:
            for i, comp in enumerate(sbom["components"]):
                if "name" not in comp:
                    errors.append(f"Component[{i}] missing name")
                if "type" not in comp:
                    errors.append(f"Component[{i}] missing type")

        return errors

    def validate_spdx(self, sbom: dict[str, Any]) -> list[str]:
        """Validate an SPDX 2.3 SBOM document.

        Args:
            sbom: SPDX document dict.

        Returns:
            List of validation errors (empty = valid).
        """
        errors: list[str] = []

        if sbom.get("spdxVersion") != "SPDX-2.3":
            errors.append("Missing or invalid spdxVersion")

        if "dataLicense" not in sbom:
            errors.append("Missing dataLicense")

        if "SPDXID" not in sbom:
            errors.append("Missing document SPDXID")

        if "creationInfo" not in sbom:
            errors.append("Missing creationInfo")
        else:
            ci = sbom["creationInfo"]
            if "created" not in ci:
                errors.append("Missing creationInfo.created")

        if "packages" not in sbom:
            errors.append("Missing packages list")
        elif not isinstance(sbom["packages"], list):
            errors.append("packages must be a list")
        else:
            for i, pkg in enumerate(sbom["packages"]):
                if "SPDXID" not in pkg:
                    errors.append(f"Package[{i}] missing SPDXID")
                if "name" not in pkg:
                    errors.append(f"Package[{i}] missing name")

        return errors

    def validate_modelchain(self, sbom: dict[str, Any]) -> list[str]:
        """Validate a ModelChain native SBOM document.

        Args:
            sbom: ModelChain document dict.

        Returns:
            List of validation errors (empty = valid).
        """
        errors: list[str] = []

        if "modelchain" not in sbom:
            errors.append("Missing modelchain wrapper")
        else:
            mc = sbom["modelchain"]
            if mc.get("format") != "modelchain":
                errors.append("Invalid modelchain format")

        if "model" not in sbom:
            errors.append("Missing model section")
        else:
            m = sbom["model"]
            if "name" not in m:
                errors.append("Model missing name")
            if "version" not in m:
                errors.append("Model missing version")

        if "datasets" in sbom and not isinstance(sbom["datasets"], list):
            errors.append("datasets must be a list")
        if "adapters" in sbom and not isinstance(sbom["adapters"], list):
            errors.append("adapters must be a list")
        if "dependencies" in sbom and not isinstance(sbom["dependencies"], list):
            errors.append("dependencies must be a list")

        return errors

    def validate(self, sbom: dict[str, Any], fmt: str = "modelchain") -> list[str]:
        """Validate an SBOM in the specified format.

        Args:
            sbom: SBOM document dict.
            fmt: Format: modelchain, cyclonedx, spdx.

        Returns:
            List of validation errors.
        """
        validators = {
            "modelchain": self.validate_modelchain,
            "cyclonedx": self.validate_cyclonedx,
            "spdx": self.validate_spdx,
        }
        validator = validators.get(fmt)
        if validator is None:
            return [f"Unknown format: {fmt}"]
        return validator(sbom)

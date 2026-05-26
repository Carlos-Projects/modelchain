from __future__ import annotations

from pathlib import Path
from typing import Any

from modelchain.utils.crypto import hash_file, verify_hash


class VerificationResult:
    """Result of a provenance verification check."""

    def __init__(
        self,
        component_id: str,
        component_name: str,
        verified: bool,
        expected_hash: str,
        computed_hash: str,
        algorithm: str = "sha256",
        errors: list[str] | None = None,
    ) -> None:
        self.component_id = component_id
        self.component_name = component_name
        self.verified = verified
        self.expected_hash = expected_hash
        self.computed_hash = computed_hash
        self.algorithm = algorithm
        self.errors = errors or []


class ProvenanceVerifier:
    """Verifies cryptographic integrity of model components."""

    def __init__(self, algorithm: str = "sha256"):
        self.algorithm = algorithm

    def verify_component(
        self,
        component_id: str,
        component_name: str,
        file_path: str | Path,
        expected_hash: str,
    ) -> VerificationResult:
        """Verify a single component's integrity.

        Args:
            component_id: Unique component identifier.
            component_name: Human-readable component name.
            file_path: Path to the component file.
            expected_hash: Expected cryptographic hash.

        Returns:
            VerificationResult with the outcome.
        """
        errors: list[str] = []
        p = Path(file_path).resolve()
        try:
            computed = hash_file(p, self.algorithm)
        except FileNotFoundError:
            return VerificationResult(
                component_id=component_id,
                component_name=component_name,
                verified=False,
                expected_hash=expected_hash,
                computed_hash="",
                algorithm=self.algorithm,
                errors=[f"File not found: {p.name}"],
            )
        except (OSError, ValueError) as e:
            errors.append(str(e))
            return VerificationResult(
                component_id=component_id,
                component_name=component_name,
                verified=False,
                expected_hash=expected_hash,
                computed_hash="",
                algorithm=self.algorithm,
                errors=errors,
            )

        is_verified = verify_hash(p, expected_hash, self.algorithm)

        return VerificationResult(
            component_id=component_id,
            component_name=component_name,
            verified=is_verified,
            expected_hash=expected_hash,
            computed_hash=computed,
            algorithm=self.algorithm,
        )

    def verify_manifest(
        self,
        manifest: dict[str, str],
        base_path: str | Path = ".",
    ) -> list[VerificationResult]:
        """Verify all entries in a checksum manifest.

        Args:
            manifest: Dict mapping filenames to expected hashes.
            base_path: Base directory for resolving file paths.

        Returns:
            List of VerificationResult for each manifest entry.
        """
        bp = Path(base_path).resolve()
        results: list[VerificationResult] = []
        for filename, expected_hash in manifest.items():
            # Reject path traversal in manifest filenames
            clean_name = Path(filename).name
            if clean_name != filename:
                results.append(
                    VerificationResult(
                        component_id=filename,
                        component_name=filename,
                        verified=False,
                        expected_hash=expected_hash,
                        computed_hash="",
                        algorithm=self.algorithm,
                        errors=[f"Path traversal detected in manifest entry: {filename}"],
                    )
                )
                continue
            file_path = bp / clean_name
            result = self.verify_component(
                component_id=filename,
                component_name=filename,
                file_path=file_path,
                expected_hash=expected_hash,
            )
            results.append(result)
        return results

    def verify_model_graph(
        self,
        provenance_data: dict[str, Any],
        base_path: str | Path = ".",
    ) -> dict[str, Any]:
        """Verify all components in a provenance graph.

        Args:
            provenance_data: Serialized provenance graph.
            base_path: Base directory for resolving file paths.

        Returns:
            Dict with verification summary.
        """
        results: list[VerificationResult] = []
        bp = Path(base_path).resolve()

        for node in provenance_data.get("nodes", []):
            if node.get("hash"):
                node_name = str(node.get("name", ""))
                # Sanitize node name for use as filename
                safe_name = Path(node_name).name
                path = bp / f"{safe_name}.bin"
                result = self.verify_component(
                    component_id=node["id"],
                    component_name=node_name,
                    file_path=path,
                    expected_hash=node["hash"],
                )
                results.append(result)

        verified_count = sum(1 for r in results if r.verified)
        return {
            "total": len(results),
            "verified": verified_count,
            "failed": len(results) - verified_count,
            "results": [
                {
                    "component": r.component_name,
                    "verified": r.verified,
                    "expected_hash": r.expected_hash,
                    "computed_hash": r.computed_hash,
                    "errors": r.errors,
                }
                for r in results
            ],
        }

import hashlib
import hmac
from pathlib import Path

ALLOWED_ALGORITHMS: set[str] = {"sha256", "sha384", "sha512"}


def _validate_algorithm(algorithm: str) -> None:
    """Validate the hash algorithm against an allowlist.

    Args:
        algorithm: Hash algorithm name.

    Raises:
        ValueError: If algorithm is not in the allowed set.
    """
    if algorithm not in ALLOWED_ALGORITHMS:
        msg = f"Unsupported hash algorithm '{algorithm}'. Allowed: {', '.join(sorted(ALLOWED_ALGORITHMS))}"
        raise ValueError(msg)


def hash_file(path: str | Path, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of a file.

    Args:
        path: Path to the file (will be resolved).
        algorithm: Hash algorithm (default: sha256). Must be in ALLOWED_ALGORITHMS.

    Returns:
        Hex digest string.

    Raises:
        ValueError: If algorithm is not allowed.
        FileNotFoundError: If the file does not exist.
    """
    _validate_algorithm(algorithm)
    p = Path(path).resolve()
    h = hashlib.new(algorithm)
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of byte data.

    Args:
        data: Bytes to hash.
        algorithm: Hash algorithm (default: sha256). Must be in ALLOWED_ALGORITHMS.

    Returns:
        Hex digest string.
    """
    _validate_algorithm(algorithm)
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def verify_hash(path: str | Path, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Verify a file matches an expected hash using constant-time comparison.

    Args:
        path: Path to the file.
        expected_hash: Expected hex digest.
        algorithm: Hash algorithm (default: sha256).

    Returns:
        True if the hash matches, False otherwise.
    """
    computed = hash_file(path, algorithm)
    return hmac.compare_digest(computed, expected_hash.lower())


def generate_checksum_manifest(
    paths: list[str | Path],
    algorithm: str = "sha256",
) -> dict[str, str]:
    """Generate a checksum manifest for a list of files.

    All paths are resolved before hashing.

    Args:
        paths: List of file paths.
        algorithm: Hash algorithm (default: sha256).

    Returns:
        Dict mapping filename to hex digest.
    """
    manifest: dict[str, str] = {}
    for path in paths:
        p = Path(path).resolve()
        manifest[p.name] = hash_file(p, algorithm)
    return manifest


__all__ = [
    "ALLOWED_ALGORITHMS",
    "generate_checksum_manifest",
    "hash_bytes",
    "hash_file",
    "verify_hash",
]

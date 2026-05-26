import hashlib
from pathlib import Path


def hash_file(path: str | Path, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of a file.

    Args:
        path: Path to the file.
        algorithm: Hash algorithm (default: sha256).

    Returns:
        Hex digest string.
    """
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of byte data.

    Args:
        data: Bytes to hash.
        algorithm: Hash algorithm (default: sha256).

    Returns:
        Hex digest string.
    """
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def verify_hash(path: str | Path, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Verify a file matches an expected hash.

    Args:
        path: Path to the file.
        expected_hash: Expected hex digest.
        algorithm: Hash algorithm (default: sha256).

    Returns:
        True if the hash matches, False otherwise.
    """
    computed = hash_file(path, algorithm)
    return computed == expected_hash.lower()


def generate_checksum_manifest(
    paths: list[str | Path],
    algorithm: str = "sha256",
) -> dict[str, str]:
    """Generate a checksum manifest for a list of files.

    Args:
        paths: List of file paths.
        algorithm: Hash algorithm (default: sha256).

    Returns:
        Dict mapping filename to hex digest.
    """
    manifest: dict[str, str] = {}
    for path in paths:
        p = Path(path)
        manifest[p.name] = hash_file(p, algorithm)
    return manifest

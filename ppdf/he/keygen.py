"""Algorithm 1 key generation for the paper's PPDF prototype.

This module is an educational reconstruction of Algorithm 1 from:
    T. B. Ogunseyi and O. M. Adedayo, "Cryptographic Techniques for Data
    Privacy in Digital Forensics", IEEE Access, 2023.

The paper delegates the complete polynomial-ring definition to reference
[77].  This implementation makes the explicit, documented engineering
assumption f(x) = x**n + 1.  It is therefore suitable for the team's local
prototype and reproducibility work, but it is not a production cryptosystem.
Install the dependencies from `requirements.txt` before importing this module.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from random import Random
from typing import Mapping, Sequence

from sympy import Poly, ZZ, QQ, invert, resultant, symbols


X = symbols("x")


class KeyGenerationError(RuntimeError):
    """Raised when a valid key cannot be generated within the retry limit."""


@dataclass(frozen=True)
class PublicKey:
    """Public key returned by Algorithm 1."""

    d: int
    r: int

    def as_dict(self) -> dict[str, int]:
        return {"d": self.d, "r": self.r}


@dataclass(frozen=True)
class PrivateKey:
    """Private key coefficients (the paper's ``w_i`` values)."""

    w: tuple[int, ...]

    def as_list(self) -> list[int]:
        return list(self.w)


@dataclass(frozen=True)
class KeyPair:
    public_key: PublicKey
    private_key: PrivateKey
    dimension: int
    coefficient_bits: int
    attempts: int


class _RandomSource:
    """Small adapter so production randomness and deterministic tests share code."""

    def __init__(self, seed: int | None = None):
        self._rng = Random(seed) if seed is not None else secrets.SystemRandom()

    def randbits(self, bits: int) -> int:
        return self._rng.getrandbits(bits)


def _validate_parameters(dimension: int, coefficient_bits: int, max_attempts: int) -> None:
    if not isinstance(dimension, int) or isinstance(dimension, bool) or dimension < 2:
        raise ValueError("dimension must be an integer >= 2")
    if not isinstance(coefficient_bits, int) or isinstance(coefficient_bits, bool) or coefficient_bits < 2:
        raise ValueError("coefficient_bits must be an integer >= 2")
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise ValueError("max_attempts must be an integer >= 1")


def modulus_polynomial(dimension: int) -> Poly:
    """Return the explicit reconstruction choice f(x) = x**n + 1."""

    _validate_parameters(dimension, 2, 1)
    return Poly(X**dimension + 1, X, domain=ZZ)


def random_vector(
    dimension: int,
    coefficient_bits: int,
    rng: _RandomSource | None = None,
) -> tuple[int, ...]:
    """Generate v with t-bit coefficients and an odd coefficient sum."""

    _validate_parameters(dimension, coefficient_bits, 1)
    source = rng or _RandomSource()
    values = [source.randbits(coefficient_bits) for _ in range(dimension)]

    # Algorithm 1 requires sum(v_i) == 1 (mod 2).  Flipping the low bit of
    # the final coefficient preserves its t-bit range for t >= 2.
    if sum(values) % 2 != 1:
        values[-1] ^= 1
    return tuple(values)


def vector_to_polynomial(values: Sequence[int]) -> Poly:
    """Convert ascending coefficient order [v0, v1, ...] to a SymPy Poly."""

    if not values:
        raise ValueError("coefficient vector cannot be empty")
    expression = sum(int(value) * X**index for index, value in enumerate(values))
    return Poly(expression, X, domain=ZZ)


def _coefficient_vector(poly: Poly, dimension: int) -> tuple[int, ...]:
    """Return exactly `dimension` coefficients in ascending order."""

    reduced = poly.rem(modulus_polynomial(dimension))
    return tuple(int(reduced.nth(index)) for index in range(dimension))


def resultant_and_w(
    vector: Sequence[int],
    dimension: int,
) -> tuple[int, tuple[int, ...]]:
    """Compute d and w such that w(x)v(x) = d (mod f(x)).

    `invert` is performed over QQ because v(x) is generally not a unit over
    ZZ. Multiplying the rational inverse by the resultant produces the
    integer adjugate polynomial used as w(x).
    """

    if len(vector) != dimension:
        raise ValueError("vector length must equal dimension")
    v = vector_to_polynomial(vector)
    f = modulus_polynomial(dimension)
    d = abs(int(resultant(v.as_expr(), f.as_expr(), X)))
    if d <= 1:
        raise KeyGenerationError("resultant is too small to form a usable modulus")

    try:
        inverse = invert(v, f, domain=QQ)
    except Exception as exc:  # SymPy uses several exception types by version.
        raise KeyGenerationError("v(x) is not invertible modulo f(x)") from exc

    # The resultant clears the rational denominator in the inverse.
    w = Poly(inverse.as_expr() * d, X, domain=QQ)
    if any(coefficient.q != 1 for coefficient in w.all_coeffs()):
        raise KeyGenerationError("resultant did not produce integral w(x)")
    w_integer = Poly(w.as_expr(), X, domain=ZZ)
    w_coefficients = _coefficient_vector(w_integer, dimension)
    check = (w_integer * v).rem(f)
    if check != Poly(d, X, domain=ZZ):
        raise KeyGenerationError("computed w(x) failed the defining congruence")
    return d, w_coefficients


def _derive_r(d: int, w: Sequence[int]) -> int:
    """Compute r = w0 / w1 (mod d), as specified by Algorithm 1."""

    if len(w) < 2:
        raise ValueError("w must contain at least w0 and w1")
    w0, w1 = int(w[0]), int(w[1])
    if math.gcd(w1, d) != 1:
        raise KeyGenerationError("w1 has no modular inverse modulo d")
    return (w0 * pow(w1, -1, d)) % d


def _derive_private_w(d: int, r: int, w: Sequence[int]) -> tuple[int, ...]:
    """Apply the paper's w_i = r*w_i + 1 (mod d) transformation."""

    derived = tuple((r * int(value) + 1) % d for value in w)
    if any(math.gcd(value, d) != 1 for value in derived):
        raise KeyGenerationError("derived private coefficient is not coprime to d")
    return derived


def generate_keypair(
    dimension: int = 8,
    coefficient_bits: int = 128,
    *,
    max_attempts: int = 100,
    seed: int | None = None,
) -> KeyPair:
    """Generate ``Pub_key=(d,r)`` and ``Pri_key=(w_i)``.

    ``seed`` exists only for deterministic tests and demonstrations. Omit it
    for system randomness in normal use.
    """

    _validate_parameters(dimension, coefficient_bits, max_attempts)
    rng = _RandomSource(seed)
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            vector = random_vector(dimension, coefficient_bits, rng)
            d, w = resultant_and_w(vector, dimension)
            r = _derive_r(d, w)
            private_w = _derive_private_w(d, r, w)
            return KeyPair(
                public_key=PublicKey(d=d, r=r),
                private_key=PrivateKey(w=private_w),
                dimension=dimension,
                coefficient_bits=coefficient_bits,
                attempts=attempt,
            )
        except (KeyGenerationError, ZeroDivisionError, ValueError) as exc:
            last_error = exc

    raise KeyGenerationError(
        f"could not generate a valid key after {max_attempts} attempts"
        + (f": {last_error}" if last_error else "")
    )


def _atomic_write(path: Path, content: str, mode: int) -> None:
    """Write a file atomically, then apply the requested local permission."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        try:
            os.chmod(path, mode)
        except OSError:
            # Windows/mounted filesystems may not implement POSIX modes.
            pass
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def save_public_key(public_key: PublicKey, path: str | Path = "public_key.json") -> Path:
    """Save the public key as readable JSON."""

    destination = Path(path)
    payload = json.dumps(public_key.as_dict(), indent=2) + "\n"
    _atomic_write(destination, payload, 0o644)
    return destination


def _read_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def save_private_key_to_env(
    private_key: PrivateKey,
    path: str | Path = ".env",
    *,
    dimension: int | None = None,
    coefficient_bits: int | None = None,
    overwrite: bool = False,
) -> Path:
    """Save private key material to a local hidden env file.

    Existing unrelated variables are preserved. Overwriting an existing
    private key requires ``overwrite=True`` to avoid accidental replacement.
    """

    destination = Path(path)
    existing = _read_env(destination)
    if "PPDF_PRIVATE_KEY_W" in existing and not overwrite:
        raise FileExistsError(
            f"{destination} already contains PPDF_PRIVATE_KEY_W; pass overwrite=True"
        )
    existing["PPDF_PRIVATE_KEY_W"] = json.dumps(private_key.as_list(), separators=(",", ":"))
    if dimension is not None:
        existing["PPDF_KEY_DIMENSION"] = str(dimension)
    if coefficient_bits is not None:
        existing["PPDF_COEFFICIENT_BITS"] = str(coefficient_bits)
    lines = [f"{key}={value}" for key, value in sorted(existing.items())]
    _atomic_write(destination, "\n".join(lines) + "\n", 0o600)
    return destination


def load_private_key_from_env(path: str | Path = ".env") -> PrivateKey:
    """Load and validate the private key from a local `.env` file."""

    values = _read_env(Path(path))
    if "PPDF_PRIVATE_KEY_W" not in values:
        raise KeyError("PPDF_PRIVATE_KEY_W is missing from the env file")
    try:
        raw = json.loads(values["PPDF_PRIVATE_KEY_W"])
        if not isinstance(raw, list) or not raw or any(not isinstance(item, int) for item in raw):
            raise ValueError
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise ValueError("PPDF_PRIVATE_KEY_W must be a JSON list of integers") from exc
    return PrivateKey(w=tuple(raw))


def load_public_key(path: str | Path = "public_key.json") -> PublicKey:
    """Load and validate the public key JSON file."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or not isinstance(payload.get("d"), int) or not isinstance(payload.get("r"), int):
        raise ValueError("public key JSON must contain integer fields d and r")
    if payload["d"] <= 1 or not 0 <= payload["r"] < payload["d"]:
        raise ValueError("public key values are outside their expected ranges")
    return PublicKey(d=payload["d"], r=payload["r"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the PPDF Algorithm 1 key pair")
    parser.add_argument("--dimension", type=int, default=8)
    parser.add_argument("--coefficient-bits", type=int, default=128)
    parser.add_argument("--max-attempts", type=int, default=100)
    parser.add_argument("--seed", type=int, default=None, help="deterministic test/demo mode only")
    parser.add_argument("--public-key", default="public_key.json")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    if args.seed is not None:
        print("WARNING: --seed is deterministic test/demo mode; do not use it for real key material.")

    try:
        pair = generate_keypair(
            dimension=args.dimension,
            coefficient_bits=args.coefficient_bits,
            max_attempts=args.max_attempts,
            seed=args.seed,
        )
        public_path = save_public_key(pair.public_key, args.public_key)
        env_path = save_private_key_to_env(
            pair.private_key,
            args.env_file,
            dimension=pair.dimension,
            coefficient_bits=pair.coefficient_bits,
            overwrite=args.overwrite,
        )
    except (ValueError, KeyError, FileExistsError, KeyGenerationError, OSError) as exc:
        parser.error(str(exc))

    print(f"Key generation succeeded after {pair.attempts} attempt(s).")
    print(f"Public key saved to {public_path}")
    print(f"Private key saved to {env_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

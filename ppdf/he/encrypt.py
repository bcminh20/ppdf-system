"""PPDF Algorithm 2 and unsigned, bit-sliced feature encryption.

This implements the paper's equation, not a security-audited HE backend.
Integer features are encoded as bits because Algorithm 4 recovers modulo 2.
No private key or random noise is serialized.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Sequence

from .keygen import PublicKey


def centered_mod(value: int, modulus: int) -> int:
    """Return the unique integer in [-d/2, d/2)."""
    if type(modulus) is not int or modulus <= 1:
        raise ValueError("modulus must be an integer > 1")
    return (value + modulus // 2) % modulus - modulus // 2


@dataclass(frozen=True)
class Algorithm2:
    public_key: PublicKey
    dimension: int = 8

    def __post_init__(self) -> None:
        d, r = self.public_key.d, self.public_key.r
        if type(d) is not int or d <= 1 or d % 2 == 0:
            raise ValueError("Algorithm 2 requires an odd integer d > 1")
        if type(r) is not int or not 0 <= r < d:
            raise ValueError("r must be an integer in [0, d)")
        if type(self.dimension) is not int or self.dimension < 2:
            raise ValueError("dimension must be an integer >= 2")
        if pow(r, self.dimension, d) != d - 1:
            raise ValueError("public key is incompatible with f(x)=x^n+1 at this dimension")

    def encrypt_bit(self, bit: int, *, noise: Sequence[int] | None = None) -> int:
        """c = [b + 2 sum(u_i r^i)]_d; explicit noise is for tests only."""
        if type(bit) is not int or bit not in (0, 1):
            raise ValueError("plaintext must be a bit; encode integers before encryption")
        if noise is None:
            noise = tuple(secrets.choice((-1, 0, 1)) for _ in range(self.dimension))
        if len(noise) != self.dimension or any(type(u) is not int or u not in (-1, 0, 1) for u in noise):
            raise ValueError("noise must contain n ternary coefficients")
        d, r = self.public_key.d, self.public_key.r
        total = bit + 2 * sum(u * pow(r, i, d) for i, u in enumerate(noise))
        return centered_mod(total, d)

    def encrypt_unsigned(self, value: int, *, bit_width: int = 8) -> list[str]:
        if type(bit_width) is not int or bit_width < 1:
            raise ValueError("bit_width must be a positive integer")
        if type(value) is not int or not 0 <= value < 2**bit_width:
            raise ValueError("feature does not fit unsigned bit_width")
        # Decimal strings preserve exact integers in JavaScript/JSON consumers.
        return [str(self.encrypt_bit((value >> bit) & 1)) for bit in range(bit_width)]

    def encrypt_vector(self, vector: Sequence[int], *, bit_width: int = 8) -> list[list[str]]:
        if len(vector) != 2:
            raise ValueError("expected V_i=[keyword_count, concealment_score]")
        return [self.encrypt_unsigned(value, bit_width=bit_width) for value in vector]

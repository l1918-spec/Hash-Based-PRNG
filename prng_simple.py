

import hashlib
import os
from typing import Optional


class HashPRNG:
    """

    -------
    >>> prng = HashPRNG(seed=b"my secret seed")
    >>> prng.generate_bytes(16).hex()
    'a3f1...'
    """

    HASH_ALGO = "sha256"
    STATE_SIZE = 32

    def __init__(self, seed: Optional[bytes] = None) -> None:
        if seed is None:
            seed = os.urandom(self.STATE_SIZE)

        self._state: bytes = self._hash(seed)
        self._output_count: int = 0



    def _hash(self, data: bytes) -> bytes:
        return hashlib.new(self.HASH_ALGO, data).digest()

    def _advance(self) -> bytes:

        output_block = self._hash(self._state)

        counter_bytes = self._output_count.to_bytes(8, "big")
        self._state = self._hash(self._state + counter_bytes)
        self._output_count += 1

        return output_block



    def generate_bytes(self, n: int) -> bytes:

        if n <= 0:
            raise ValueError("n must be a positive integer")

        result = bytearray()
        while len(result) < n:
            result.extend(self._advance())

        return bytes(result[:n])

    def generate_int(self, low: int, high: int) -> int:

        if low > high:
            raise ValueError("low must be <= high")

        range_size = high - low + 1
        num_bytes = (range_size.bit_length() + 7) // 8
        mask = (1 << range_size.bit_length()) - 1
        while True:
            candidate = int.from_bytes(self.generate_bytes(num_bytes), "big") & mask
            if candidate < range_size:
                return low + candidate

    def generate_float(self) -> float:

        raw = int.from_bytes(self.generate_bytes(8), "big")
        return raw / (2**64)

    def reseed(self, new_seed: bytes) -> None:

        self._state = self._hash(self._state + new_seed)
        self._output_count = 0

    def __repr__(self) -> str:
        return (
            f"HashPRNG("
            f"algo={self.HASH_ALGO}, "
            f"outputs_generated={self._output_count})"
        )


if __name__ == "__main__":
    print("=" * 55)
    print("  Simple Hash-Based PRNG — SHA-256 Demo")
    print("=" * 55)

    prng_fixed = HashPRNG(seed=b"university_demo_seed_2025")
    print("\n[Fixed seed — reproducible output]")
    print(f"  16 bytes : {prng_fixed.generate_bytes(16).hex()}")
    print(f"  Int [1,100]: {prng_fixed.generate_int(1, 100)}")
    print(f"  Float     : {prng_fixed.generate_float():.6f}")

    prng_fixed2 = HashPRNG(seed=b"university_demo_seed_2025")
    print("\n[Same seed — must produce identical output]")
    print(f"  16 bytes : {prng_fixed2.generate_bytes(16).hex()}")

    prng_random = HashPRNG()
    print("\n[Random seed — unpredictable output]")
    print(f"  16 bytes : {prng_random.generate_bytes(16).hex()}")
    print(f"  {prng_random}")

    print("\n✓ Simple PRNG working correctly.")
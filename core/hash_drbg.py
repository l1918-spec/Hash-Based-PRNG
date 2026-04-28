"""
core/hash_drbg.py
────────────────────────────────────────────────────────────────
NIST SP 800-90A Hash_DRBG using SHA-256.

References
----------
NIST SP 800-90A Rev. 1, Section 10.1.1

State variables
---------------
V  : 55-byte working value updated every generate call.
C  : 55-byte constant derived at instantiate / reseed time.
reseed_counter : number of generate calls since last seeding.
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import Optional


# ------------------------------------------------------------------
# Helper — Hash_df (section 10.3.1)
# ------------------------------------------------------------------

def hash_df(input_string: bytes, no_of_bits_to_return: int) -> bytes:
    """
    NIST Hash Derivation Function (Hash_df).

    Parameters
    ----------
    input_string : bytes
        The input to hash.
    no_of_bits_to_return : int
        Must be a multiple of 8.

    Returns
    -------
    bytes
        Derived material of length ``no_of_bits_to_return // 8``.

    Raises
    ------
    ValueError
        If *no_of_bits_to_return* is not a multiple of 8.
    """
    if no_of_bits_to_return % 8 != 0:
        raise ValueError("no_of_bits_to_return must be a multiple of 8")

    len_in_bytes = no_of_bits_to_return // 8
    result = bytearray()
    counter = 1

    while len(result) < len_in_bytes:
        counter_byte = bytes([counter])
        length_bytes = struct.pack(">I", no_of_bits_to_return)
        digest = hashlib.sha256(counter_byte + length_bytes + input_string).digest()
        result.extend(digest)
        counter += 1

    return bytes(result[:len_in_bytes])


# ------------------------------------------------------------------
# Main class
# ------------------------------------------------------------------

class HashDRBG:
    """
    NIST SP 800-90A Hash_DRBG instantiated with SHA-256.

    Parameters
    ----------
    entropy_input : bytes, optional
        At least 32 bytes of entropy.  Defaults to ``os.urandom(32)``.
    nonce : bytes, optional
        128-bit nonce.  Defaults to ``os.urandom(16)``.
    personalization_string : bytes
        Optional domain-separation string (may be empty).

    Examples
    --------
    >>> drbg = HashDRBG(personalization_string=b"demo")
    >>> len(drbg.generate(32))
    32
    """

    HASH_ALGO: str = "sha256"
    DIGEST_LEN: int = 32          # SHA-256 output length in bytes
    SEED_LEN: int = 55            # NIST-specified seedlen for SHA-256
    SECURITY_BITS: int = 256
    RESEED_INTERVAL: int = 2**48  # NIST maximum requests between reseeds
    MAX_BYTES_PER_REQUEST: int = 7500  # NIST limit

    def __init__(
        self,
        entropy_input: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        personalization_string: bytes = b"",
    ) -> None:
        if entropy_input is None:
            entropy_input = os.urandom(32)
        if nonce is None:
            nonce = os.urandom(16)

        self._V: bytes
        self._C: bytes
        self._reseed_counter: int

        self._instantiate(entropy_input, nonce, personalization_string)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _H(self, data: bytes) -> bytes:
        """SHA-256 hash."""
        return hashlib.sha256(data).digest()

    def _hashgen(self, requested_bytes: int) -> bytes:
        """
        NIST Hashgen function (section 10.1.1.4).

        Generates *requested_bytes* by iterating H over a local copy of V.
        """
        data = self._V
        result = bytearray()
        blocks_needed = (requested_bytes + self.DIGEST_LEN - 1) // self.DIGEST_LEN

        for _ in range(blocks_needed):
            result.extend(self._H(data))
            data = self._add_mod(data, b"\x01")

        return bytes(result[:requested_bytes])

    def _add_mod(self, a: bytes, b: bytes) -> bytes:
        """
        Modular addition of two big-endian byte strings.

        Result has the same length as *a*.
        """
        if len(b) < len(a):
            b = b.rjust(len(a), b"\x00")
        int_a = int.from_bytes(a, "big")
        int_b = int.from_bytes(b, "big")
        result = (int_a + int_b) % (2 ** (len(a) * 8))
        return result.to_bytes(len(a), "big")

    # ------------------------------------------------------------------
    # NIST operations
    # ------------------------------------------------------------------

    def _instantiate(
        self,
        entropy_input: bytes,
        nonce: bytes,
        personalization_string: bytes,
    ) -> None:
        """NIST Hash_DRBG Instantiate function (section 10.1.1.2)."""
        seed_material = entropy_input + nonce + personalization_string
        self._V = hash_df(seed_material, self.SEED_LEN * 8)
        self._C = hash_df(b"\x00" + self._V, self.SEED_LEN * 8)
        self._reseed_counter = 1

    def _do_reseed(
        self,
        entropy_input: bytes,
        additional_input: bytes = b"",
    ) -> None:
        """NIST Hash_DRBG Reseed function (section 10.1.1.3)."""
        seed_material = b"\x01" + self._V + entropy_input + additional_input
        self._V = hash_df(seed_material, self.SEED_LEN * 8)
        self._C = hash_df(b"\x00" + self._V, self.SEED_LEN * 8)
        self._reseed_counter = 1

    def _update_state(
        self,
        returned_bits: bytes,
        additional_input: bytes = b"",
    ) -> None:
        """NIST Hash_DRBG state update after each generate call."""
        H = self._H(b"\x03" + self._V)
        reseed_bytes = self._reseed_counter.to_bytes(4, "big")

        new_V = self._V
        new_V = self._add_mod(new_V, H)
        new_V = self._add_mod(new_V, self._C)
        new_V = self._add_mod(new_V, reseed_bytes)

        if additional_input:
            additional_H = self._H(b"\x02" + self._V + additional_input)
            new_V = self._add_mod(new_V, additional_H)

        self._V = new_V

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        num_bytes: int,
        additional_input: bytes = b"",
    ) -> bytes:
        """
        Generate *num_bytes* of pseudorandom data.

        Parameters
        ----------
        num_bytes : int
            Number of bytes to return (max 7 500 per NIST).
        additional_input : bytes
            Optional domain-separation material (e.g. session ID).

        Returns
        -------
        bytes

        Raises
        ------
        ValueError
            If *num_bytes* exceeds ``MAX_BYTES_PER_REQUEST``.
        ReseedRequiredError
            If ``reseed_counter`` has exceeded ``RESEED_INTERVAL``.
        """
        if num_bytes > self.MAX_BYTES_PER_REQUEST:
            raise ValueError(
                f"Requested {num_bytes} bytes but NIST limit is "
                f"{self.MAX_BYTES_PER_REQUEST} per call."
            )
        if self._reseed_counter > self.RESEED_INTERVAL:
            raise ReseedRequiredError(
                "Reseed interval exceeded — call reseed() with fresh entropy."
            )

        if additional_input:
            w = self._H(b"\x02" + self._V + additional_input)
            self._V = self._add_mod(self._V, w)

        returned_bits = self._hashgen(num_bytes)
        self._update_state(returned_bits, additional_input)
        self._reseed_counter += 1
        return returned_bits

    def reseed(
        self,
        entropy_input: Optional[bytes] = None,
        additional_input: bytes = b"",
    ) -> None:
        """
        Reseed the DRBG with fresh entropy.

        Parameters
        ----------
        entropy_input : bytes, optional
            If *None*, ``os.urandom(32)`` is used automatically.
        additional_input : bytes
            Optional additional data to mix in.
        """
        if entropy_input is None:
            entropy_input = os.urandom(32)
        self._do_reseed(entropy_input, additional_input)

    @property
    def reseed_counter(self) -> int:
        """Number of generate calls since last instantiate / reseed."""
        return self._reseed_counter

    def __repr__(self) -> str:
        return (
            f"HashDRBG("
            f"algo={self.HASH_ALGO!r}, "
            f"security_bits={self.SECURITY_BITS}, "
            f"reseed_counter={self._reseed_counter})"
        )


class ReseedRequiredError(Exception):
    """Raised when the DRBG has exceeded its reseed interval."""
    pass


# ------------------------------------------------------------------
# Quick smoke-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 55)
    print("  NIST Hash_DRBG (SP 800-90A) — SHA-256 Demo")
    print("=" * 55)

    drbg = HashDRBG(personalization_string=b"university_module_2025")
    print(f"\nCreated: {drbg}")

    print("\n[Generate 32 bytes]")
    out1 = drbg.generate(32)
    print(f"  Output : {out1.hex()}")
    print(f"  Counter: {drbg.reseed_counter}")

    print("\n[Generate with additional input]")
    out2 = drbg.generate(32, additional_input=b"context_A")
    print(f"  Output : {out2.hex()}")
    print(f"\n  out1 == out2 : {out1 == out2}  ← must be False")

    print("\n[Reseed with fresh entropy]")
    drbg.reseed()
    print(f"  Counter reset: {drbg.reseed_counter}")

    out3 = drbg.generate(32)
    print(f"  Post-reseed output: {out3.hex()}")
    print("\n✓ Hash_DRBG working correctly.")

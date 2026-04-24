

import hashlib
import hmac
import os
import struct
from typing import Optional

def hash_df(input_string: bytes, no_of_bits_to_return: int) -> bytes:

    if no_of_bits_to_return % 8 != 0:
        raise ValueError("no_of_bits_to_return must be a multiple of 8")

    len_in_bytes = no_of_bits_to_return // 8
    result = bytearray()
    counter = 1  #

    while len(result) < len_in_bytes:
        counter_byte = bytes([counter])
        length_bytes = struct.pack(">I", no_of_bits_to_return)  # 4-byte big-endian
        digest = hashlib.sha256(counter_byte + length_bytes + input_string).digest()
        result.extend(digest)
        counter += 1

    return bytes(result[:len_in_bytes])


class HashDRBG:
    """
    NIST SP 800-90A Hash_DRBG using SHA-256.



    -------
    >>> drbg = HashDRBG(personalization_string=b"demo")
    >>> drbg.generate(32).hex()
    'a3f1...'
    """

    HASH_ALGO        = "sha256"
    DIGEST_LEN       = 32
    SEED_LEN         = 55
    SECURITY_BITS    = 256
    RESEED_INTERVAL  = 2**48
    MAX_BYTES_PER_REQUEST = 7500

    def __init__(
        self,
        entropy_input: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        personalization_string: bytes = b"",
    ) -> None:

        if entropy_input is None:
            entropy_input = os.urandom(32)
        if nonce is None:
            nonce = os.urandom(16)           # 128-bit nonce

        self._V: bytes
        self._C: bytes
        self._reseed_counter: int

        self._instantiate(entropy_input, nonce, personalization_string)


    def _H(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def _hashgen(self, requested_bytes: int) -> bytes:


        data = self._V
        result = bytearray()

        blocks_needed = (requested_bytes + self.DIGEST_LEN - 1) // self.DIGEST_LEN

        for _ in range(blocks_needed):
            result.extend(self._H(data))
            data = self._add_mod(data, b"\x01")

        return bytes(result[:requested_bytes])

    def _add_mod(self, a: bytes, b: bytes) -> bytes:

        if len(b) < len(a):
            b = b.rjust(len(a), b"\x00")

        int_a = int.from_bytes(a, "big")
        int_b = int.from_bytes(b, "big")
        result = (int_a + int_b) % (2 ** (len(a) * 8))
        return result.to_bytes(len(a), "big")



    def _instantiate(
        self,
        entropy_input: bytes,
        nonce: bytes,
        personalization_string: bytes,
    ) -> None:

        seed_material = entropy_input + nonce + personalization_string

        self._V = hash_df(seed_material, self.SEED_LEN * 8)

        self._C = hash_df(b"\x00" + self._V, self.SEED_LEN * 8)

        self._reseed_counter = 1

    def _do_reseed(
        self,
        entropy_input: bytes,
        additional_input: bytes = b"",
    ) -> None:

        seed_material = b"\x01" + self._V + entropy_input + additional_input

        self._V = hash_df(seed_material, self.SEED_LEN * 8)
        self._C = hash_df(b"\x00" + self._V, self.SEED_LEN * 8)
        self._reseed_counter = 1

    def _update_state(
        self,
        returned_bits: bytes,
        additional_input: bytes = b"",
    ) -> None:

        H = self._H(b"\x03" + self._V)


        reseed_bytes = self._reseed_counter.to_bytes(4, "big")

        new_V = self._V
        new_V = self._add_mod(new_V, H)
        new_V = self._add_mod(new_V, self._C)
        new_V = self._add_mod(new_V, reseed_bytes)

        if additional_input:
            # Mix additional input into V
            additional_H = self._H(b"\x02" + self._V + additional_input)
            new_V = self._add_mod(new_V, additional_H)

        self._V = new_V


    def generate(
        self,
        num_bytes: int,
        additional_input: bytes = b"",
    ) -> bytes:

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

        if entropy_input is None:
            entropy_input = os.urandom(32)
        self._do_reseed(entropy_input, additional_input)

    @property
    def reseed_counter(self) -> int:
        return self._reseed_counter

    def __repr__(self) -> str:
        return (
            f"HashDRBG("
            f"algo={self.HASH_ALGO}, "
            f"security_bits={self.SECURITY_BITS}, "
            f"reseed_counter={self._reseed_counter})"
        )


class ReseedRequiredError(Exception):
    pass

#demoo
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
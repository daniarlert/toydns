from struct import Struct
from typing import Iterator


def unpack_from(struct: Struct, buffer: bytes, offset: int) -> tuple[tuple, int]:
    return struct.unpack_from(buffer, offset), offset + struct.size


def encode_name(name: str) -> Iterator[bytes]:
    name_bytes = name.encode("ascii")
    parts = name_bytes.split(b".")
    for part in parts:
        yield bytes([len(part)])
        yield part

    yield b"\x00"


def decode_name(buffer: bytes, offset: int = 0) -> tuple[str, int]:
    parts: list[str] = []
    seen: set[int] = set()

    def decode(offset: int) -> int:
        seen.add(offset)
        while n := buffer[offset]:
            offset += 1
            if n & 0b1100_0000:
                pos = ((n & 0b0011_1111) << 8) + buffer[offset]
                if pos in seen:
                    raise ValueError("Recursion while decoding DNS name")

                decode(pos)
                break

            start = offset
            offset += n
            parts.append(buffer[start:offset].decode("ascii"))

        return offset + 1

    offset = decode(offset)
    return ".".join(parts), offset

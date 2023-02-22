from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum, StrEnum, auto
from struct import Struct

from bidict import bidict


class LinkLayerTypes(IntEnum):
    none = 0
    ethernet = auto()


class Endianness(StrEnum):
    big_endian = ">"
    little_endian = "<"


class SecondsPartsUnit(float, Enum):
    micros = 1e6
    nanos = 1e9


PCAP_MAGICS = bidict(
    [
        (b"\xd4\xc3\xb2\xa1", (Endianness.little_endian, SecondsPartsUnit.micros)),
        (b"\xd4\x3c\xb2\xa1", (Endianness.little_endian, SecondsPartsUnit.nanos)),
        (b"\xa1\xb2\xc3\xd4", (Endianness.big_endian, SecondsPartsUnit.micros)),
        (b"\xa1\xb2\x3c\xd4", (Endianness.big_endian, SecondsPartsUnit.nanos)),
    ]
)

NETWORK_CAPTURE_HEADER_STRUCTURE = {
    Endianness.big_endian: Struct(f"{Endianness.big_endian}HHiIII"),
    Endianness.little_endian: Struct(f"{Endianness.little_endian}HHiIII"),
}

CAPTURED_PACKET_HEADER_STRUCTURE = {
    Endianness.big_endian: Struct(f"{Endianness.big_endian}IIII"),
    Endianness.little_endian: Struct(f"{Endianness.little_endian}IIII"),
}


@dataclass
class CapturedPacket:
    data: bytes
    capture_time: datetime
    link_layer_type: LinkLayerTypes = LinkLayerTypes.ethernet
    original_length: int | None = None

    def __post_init__(self):
        self.original_length = self.original_length or len(self.data)

    @property
    def is_fully_captured(self):
        return self.original_length == len(self.data)

    def __iter__(self):
        return iter(self.data)

    def __getitem__(self, item):
        return self.data[item]

    def __repr__(self):
        return f"<CapturedPacket - {len(self.data)} bytes captured at {self.capture_time} >"

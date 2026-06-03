from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum, auto
from functools import total_ordering
from struct import Struct
from typing import TYPE_CHECKING, SupportsIndex

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from typing import BinaryIO


class LinkLayerTypes(IntEnum):
    none = 0
    ethernet = auto()


class Endianness(StrEnum):
    big_endian = ">"
    little_endian = "<"


class SecondsPartsUnit(IntEnum):
    micros = 1_000_000
    nanos = 1_000_000_000


PCAP_MAGIC_BY_FORMAT: dict[tuple[Endianness, SecondsPartsUnit], bytes] = {
    (Endianness.little_endian, SecondsPartsUnit.micros): b"\xd4\xc3\xb2\xa1",
    (Endianness.little_endian, SecondsPartsUnit.nanos): b"\xd4\x3c\xb2\xa1",
    (Endianness.big_endian, SecondsPartsUnit.micros): b"\xa1\xb2\xc3\xd4",
    (Endianness.big_endian, SecondsPartsUnit.nanos): b"\xa1\xb2\x3c\xd4",
}

PCAP_FORMAT_BY_MAGIC: dict[bytes, tuple[Endianness, SecondsPartsUnit]] = {
    magic: format_ for format_, magic in PCAP_MAGIC_BY_FORMAT.items()
}

NETWORK_CAPTURE_HEADER_STRUCTURE = {
    Endianness.big_endian: Struct(f"{Endianness.big_endian:}HHiIII"),
    Endianness.little_endian: Struct(f"{Endianness.little_endian}HHiIII"),
}

CAPTURED_PACKET_HEADER_STRUCTURE = {
    Endianness.big_endian: Struct(f"{Endianness.big_endian}IIII"),
    Endianness.little_endian: Struct(f"{Endianness.little_endian}IIII"),
}


@total_ordering
@dataclass
class Timestamp:  # noqa: PLW1641
    seconds: int
    seconds_parts: int
    seconds_parts_unit: SecondsPartsUnit

    def of_unit(self, new_seconds_parts_unit: SecondsPartsUnit) -> Timestamp:
        ratio = self.seconds_parts_unit / new_seconds_parts_unit

        return Timestamp(self.seconds, int(self.seconds_parts / ratio), new_seconds_parts_unit)

    @classmethod
    def from_datetime(cls, value: datetime) -> Timestamp:
        return Timestamp(int(value.timestamp()), value.microsecond, SecondsPartsUnit.micros)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Timestamp):
            first = self
            second = other
            if self.seconds_parts_unit > other.seconds_parts_unit:
                second = other.of_unit(self.seconds_parts_unit)
            elif self.seconds_parts_unit < other.seconds_parts_unit:
                first = self.of_unit(other.seconds_parts_unit)
            return first.seconds == second.seconds and first.seconds_parts == second.seconds_parts
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Timestamp):
            first = self
            second = other
            if self.seconds_parts_unit > other.seconds_parts_unit:
                second = other.of_unit(self.seconds_parts_unit)
            elif self.seconds_parts_unit < other.seconds_parts_unit:
                first = self.of_unit(other.seconds_parts_unit)
            return first.seconds <= second.seconds and first.seconds_parts <= second.seconds_parts
        return NotImplemented


@dataclass(eq=True)
class CapturedPacket:
    data: bytes
    capture_time: Timestamp
    link_layer_type: LinkLayerTypes = LinkLayerTypes.ethernet
    original_length: int | None = None

    def __post_init__(self) -> None:
        self.original_length = self.original_length or len(self.data)

    @property
    def is_fully_captured(self) -> bool:
        return self.original_length == len(self.data)

    def __iter__(self) -> Iterator[int]:
        return iter(self.data)

    def __getitem__(self, item: SupportsIndex) -> int | bytes:
        return self.data[item]

    def __repr__(self) -> str:
        return f"<CapturedPacket - {len(self.data)} bytes captured at {self.capture_time} >"

    @classmethod
    def from_datetime(
        cls,
        data: bytes,
        capture_time: datetime,
        link_layer_type: LinkLayerTypes = LinkLayerTypes.ethernet,
        original_length: int | None = None,
    ) -> CapturedPacket:
        return CapturedPacket(data, Timestamp.from_datetime(capture_time), link_layer_type, original_length)


@dataclass
class CapFileLoader:
    reader: BinaryIO

    _header_parsed: bool = False
    _endianness: Endianness | None = field(default=None, init=False)
    _seconds_parts_unit: SecondsPartsUnit | None = field(default=None, init=False)
    _time_zone_offset_hours: int | None = field(default=None, init=False)
    _max_capture_length_octets: int | None = field(default=None, init=False)
    _link_layer_type: LinkLayerTypes | None = field(default=None, init=False)

    def _parse_header(self) -> None:
        if self._header_parsed:
            return
        self._endianness, self._seconds_parts_unit = PCAP_FORMAT_BY_MAGIC[self.reader.read(4)]
        header = NETWORK_CAPTURE_HEADER_STRUCTURE[self.endianness].unpack(self.reader.read(20))
        _, _, self._time_zone_offset_hours, _, self._max_capture_length_octets, self._link_layer_type = header
        self._header_parsed = True

    @property
    def endianness(self) -> Endianness:
        self._parse_header()
        if self._endianness is None:
            raise ValueError("Endianness is not set")
        return self._endianness

    @property
    def seconds_parts_unit(self) -> SecondsPartsUnit:
        self._parse_header()
        if self._seconds_parts_unit is None:
            raise ValueError("Seconds parts unit is not set")
        return self._seconds_parts_unit

    @property
    def time_zone_offset_hours(self) -> int:
        self._parse_header()
        if self._time_zone_offset_hours is None:
            raise ValueError("Time zone offset hours is not set")
        return self._time_zone_offset_hours

    @property
    def max_capture_length_octets(self) -> int:
        self._parse_header()
        if self._max_capture_length_octets is None:
            raise ValueError("Max capture length octets is not set")
        return self._max_capture_length_octets

    @property
    def link_layer_type(self) -> LinkLayerTypes:
        self._parse_header()
        if self._link_layer_type is None:
            raise ValueError("Link layer type is not set")
        return self._link_layer_type

    def __iter__(self) -> Iterator[CapturedPacket]:
        self._parse_header()
        captured_packet_header_structure = CAPTURED_PACKET_HEADER_STRUCTURE[self.endianness]

        while self.reader:
            header = self.reader.read(16)
            if not header:
                break
            seconds, seconds_parts, data_length, original_length = captured_packet_header_structure.unpack(header)

            yield CapturedPacket(
                data=self.reader.read(data_length),
                capture_time=Timestamp(seconds, seconds_parts, self.seconds_parts_unit),
                original_length=original_length,
                link_layer_type=self.link_layer_type,
            )


@dataclass
class CapFileDumper:
    writer: BinaryIO

    endianness: Endianness = Endianness.little_endian
    seconds_parts_unit: SecondsPartsUnit = SecondsPartsUnit.micros
    major_version: int = 2
    minor_version: int = 4
    time_zone_offset_hours: int = 0
    max_capture_length_octets: int = 0x40000
    link_layer_type: LinkLayerTypes = LinkLayerTypes.ethernet

    def dump_header(self) -> None:
        self.writer.write(PCAP_MAGIC_BY_FORMAT[(self.endianness, self.seconds_parts_unit)])
        self.writer.write(
            NETWORK_CAPTURE_HEADER_STRUCTURE[self.endianness].pack(
                self.major_version,
                self.minor_version,
                self.time_zone_offset_hours,
                0,
                self.max_capture_length_octets,
                self.link_layer_type,
            )
        )

    def dump_packet(self, captured_packet: CapturedPacket) -> None:
        capture_time = captured_packet.capture_time.of_unit(self.seconds_parts_unit)

        self.writer.write(
            CAPTURED_PACKET_HEADER_STRUCTURE[self.endianness].pack(
                capture_time.seconds + self.time_zone_offset_hours,
                capture_time.seconds_parts,
                len(captured_packet.data),
                captured_packet.original_length,
            )
        )
        self.writer.write(captured_packet.data)

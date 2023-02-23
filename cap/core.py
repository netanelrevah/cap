import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum, StrEnum, auto
from struct import Struct
from typing import BinaryIO

from bidict import bidict


class LinkLayerTypes(IntEnum):
    none = 0
    ethernet = auto()


class Endianness(StrEnum):
    big_endian = ">"
    little_endian = "<"


class SecondsPartsUnit(int, Enum):
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


@dataclass
class CapFileLoader:
    reader: BinaryIO

    _endianness: Endianness | None = field(default=None, init=False)
    _seconds_parts_unit: SecondsPartsUnit | None = field(default=None, init=False)
    _time_zone_offset_hours: int | None = field(default=None, init=False)
    _max_capture_length_octets: int | None = field(default=None, init=False)
    _link_layer_type: LinkLayerTypes | None = field(default=None, init=False)

    def _parse_magic(self):
        if self._endianness is not None or self._seconds_parts_unit is not None:
            return
        self._endianness, self._seconds_parts_unit = PCAP_MAGICS[self.reader.read(4)]

    def _parse_file_header(self):
        self._parse_magic()
        if (
            self._time_zone_offset_hours is not None
            or self._max_capture_length_octets is not None
            or self._link_layer_type is not None
        ):
            return
        header = NETWORK_CAPTURE_HEADER_STRUCTURE[self.endianness].unpack(self.reader.read(20))
        (_, _, self._time_zone_offset_hours, _, self._max_capture_length_octets, self._link_layer_type) = header

    @property
    def endianness(self) -> Endianness:
        if self._endianness is None:
            self._parse_magic()
        return self._endianness

    @property
    def seconds_parts_unit(self) -> SecondsPartsUnit:
        if self._seconds_parts_unit is None:
            self._parse_magic()
        return self._seconds_parts_unit

    @property
    def time_zone_offset_hours(self) -> int:
        if self._time_zone_offset_hours is None:
            self._parse_file_header()
        return self._time_zone_offset_hours

    @property
    def max_capture_length_octets(self) -> int:
        if self._max_capture_length_octets is None:
            self._parse_file_header()
        return self._max_capture_length_octets

    @property
    def link_layer_type(self) -> LinkLayerTypes:
        if self._link_layer_type is None:
            self._parse_file_header()
        return self._link_layer_type

    def __iter__(self):
        self._parse_magic()
        self._parse_file_header()
        captured_packet_header_structure = CAPTURED_PACKET_HEADER_STRUCTURE[self.endianness]

        while self.reader:
            header = self.reader.read(16)
            if not header:
                break
            seconds, seconds_parts, data_length, original_length = captured_packet_header_structure.unpack(header)

            yield CapturedPacket(
                data=self.reader.read(data_length),
                capture_time=datetime.fromtimestamp(
                    (float(seconds) + (seconds_parts / self.seconds_parts_unit)) - self.time_zone_offset_hours
                ),
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

    def dump_header(self):
        self.writer.write(PCAP_MAGICS.inverse[(self.endianness, self.seconds_parts_unit)])
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

    def dump_packet(self, captured_packet: CapturedPacket):
        seconds_parts, seconds = math.modf(captured_packet.capture_time.timestamp() + self.time_zone_offset_hours)

        self.writer.write(
            CAPTURED_PACKET_HEADER_STRUCTURE[self.endianness].pack(
                int(seconds),
                int(seconds_parts * self.seconds_parts_unit),
                len(captured_packet.data),
                captured_packet.original_length,
            )
        )
        self.writer.write(captured_packet.data)

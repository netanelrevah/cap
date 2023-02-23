from io import BytesIO
from typing import BinaryIO, Sequence

from cap.core import (
    CAPTURED_PACKET_HEADER_STRUCTURE,
    NETWORK_CAPTURE_HEADER_STRUCTURE,
    PCAP_MAGICS,
    CapturedPacket,
    Endianness,
    LinkLayerTypes,
    SecondsPartsUnit,
    CapFileLoader,
    CapFileDumper,
)


def load(stream: BinaryIO):
    return list(CapFileLoader(stream))


def loads(data: bytes):
    return load(BytesIO(data))


def dump(
    captured_packets: Sequence[CapturedPacket],
    writer: BinaryIO,
    write_header=True,
    endianness: Endianness = Endianness.little_endian,
    seconds_parts_unit: SecondsPartsUnit = SecondsPartsUnit.micros,
    major_version=2,
    minor_version=4,
    time_zone_offset_hours: int = 0,
    max_capture_length_octets: int = 0x40000,
    link_layer_type: LinkLayerTypes = LinkLayerTypes.ethernet,
):
    dumper = CapFileDumper(
        writer,
        endianness,
        seconds_parts_unit,
        major_version,
        minor_version,
        time_zone_offset_hours,
        max_capture_length_octets,
        link_layer_type,
    )

    if write_header:
        dumper.dump_header()
    for captured_packet in captured_packets:
        dumper.dump_packet(captured_packet)


def dumps(captured_packets: Sequence[CapturedPacket]):
    stream = BytesIO()
    dump(captured_packets, stream)
    return str(stream)


def merge(target_stream, *source_streams):
    result = []
    for source_stream in source_streams:
        result.extend(load(source_stream))
    return dump(result, target_stream)

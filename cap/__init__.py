import math
from datetime import datetime
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
)


def load(stream: BinaryIO):
    endianness, seconds_parts_type = PCAP_MAGICS[stream.read(4)]

    (
        _,
        _,
        time_zone_offset_hours,
        _,
        max_capture_length_octets,
        link_layer_type,
    ) = NETWORK_CAPTURE_HEADER_STRUCTURE[
        endianness
    ].unpack(stream.read(20))

    captured_packet_header_structure = CAPTURED_PACKET_HEADER_STRUCTURE[endianness]

    while True:
        packet_header_bytes = stream.read(16)
        if not packet_header_bytes:
            break
        packet_header_values = captured_packet_header_structure.unpack(packet_header_bytes)
        seconds, seconds_parts, data_length, original_length = packet_header_values

        yield CapturedPacket(
            data=stream.read(data_length),
            capture_time=datetime.fromtimestamp(
                (float(seconds) + (seconds_parts_type * seconds_parts)) - time_zone_offset_hours
            ),
            original_length=original_length,
            link_layer_type=link_layer_type,
        )


def loads(data: bytes):
    return load(BytesIO(data))


def dump(
    captured_packets: Sequence[CapturedPacket],
    stream: BinaryIO,
    write_header=True,
    endianness: Endianness = Endianness.little_endian,
    seconds_parts_unit: SecondsPartsUnit = SecondsPartsUnit.micros,
    major_version=2,
    minor_version=4,
    time_zone_offset_hours: int = 0,
    max_capture_length_octets: int = 0x40000,
    link_layer_type: LinkLayerTypes = LinkLayerTypes.ethernet,
):
    if write_header:
        stream.write(PCAP_MAGICS.inverse[(endianness, seconds_parts_unit)])
        stream.write(
            NETWORK_CAPTURE_HEADER_STRUCTURE[endianness].pack(
                major_version,
                minor_version,
                time_zone_offset_hours,
                0,
                max_capture_length_octets,
                link_layer_type,
            )
        )
    for captured_packet in captured_packets:
        seconds, seconds_parts = math.modf(captured_packet.capture_time.timestamp() + time_zone_offset_hours)

        stream.write(
            CAPTURED_PACKET_HEADER_STRUCTURE[endianness].pack(
                seconds,
                math.trunc(seconds_parts / seconds_parts_unit),
                len(captured_packet.data),
                captured_packet.original_length,
            )
        )


def dumps(captured_packets: Sequence[CapturedPacket]):
    stream = BytesIO()
    dump(captured_packets, stream)
    return str(stream)


def merge(target_stream, *source_streams):
    result = []
    for source_stream in source_streams:
        result.extend(load(source_stream))
    return dump(result, target_stream)

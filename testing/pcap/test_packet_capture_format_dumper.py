from io import BytesIO
from cap.pcap import PacketCaptureFormat, PacketCaptureHeaderFormat, PacketCaptureFormatDumper, \
    PacketCaptureFormatLoader, CapturedPacketFormat

__author__ = 'netanelrevah'


def test_initialize_with_defaults():
    packet_capture_header_format = PacketCaptureHeaderFormat()
    packet_capture_format = PacketCaptureFormat(packet_capture_header_format)
    packet_capture_format_dumper = PacketCaptureFormatDumper(packet_capture_format)
    assert packet_capture_format_dumper.is_big_endian is False


def test_initialize():
    packet_capture_header_format = PacketCaptureHeaderFormat()
    packet_capture_format = PacketCaptureFormat(packet_capture_header_format)
    packet_capture_format_dumper = PacketCaptureFormatDumper(packet_capture_format, True)
    assert packet_capture_format_dumper.is_big_endian is True


def test_file_header_property():
    packet_capture_header_format = PacketCaptureHeaderFormat()
    packet_capture_format = PacketCaptureFormat(packet_capture_header_format)
    packet_capture_format_dumper = PacketCaptureFormatDumper(packet_capture_format, True)
    loaded = PacketCaptureFormatLoader(BytesIO(packet_capture_format_dumper.file_header))
    assert loaded.file_header == packet_capture_header_format


def test_iteration():
    packet_capture_header_format = PacketCaptureHeaderFormat()
    captured_packet = CapturedPacketFormat(data=b'ABCD')
    packet_capture_format = PacketCaptureFormat(packet_capture_header_format, [captured_packet])
    packet_capture_format_dumper = PacketCaptureFormatDumper(packet_capture_format, True)
    loaded = PacketCaptureFormatLoader(BytesIO(packet_capture_format_dumper.file_header + b''.join(
        list(packet_capture_format_dumper))))
    assert loaded.file_header == packet_capture_header_format
    assert [captured_packet] == list(loaded)


def test_compatible_iteration():
    packet_capture_header_format = PacketCaptureHeaderFormat()
    captured_packet = CapturedPacketFormat(data=b'ABCD')
    packet_capture_format = PacketCaptureFormat(packet_capture_header_format, [captured_packet])
    packet_capture_format_dumper = PacketCaptureFormatDumper(packet_capture_format, True)
    dumped_captured_packets = []
    while True:
        try:
            dumped_captured_packets.append(packet_capture_format_dumper.__next__())
        except StopIteration:
            break
    loaded = PacketCaptureFormatLoader(BytesIO(packet_capture_format_dumper.file_header + b''.join(
        dumped_captured_packets)))
    assert loaded.file_header == packet_capture_header_format
    assert [captured_packet] == list(loaded)

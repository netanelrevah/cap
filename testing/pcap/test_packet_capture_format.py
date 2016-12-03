from io import BytesIO
from pkt.captures import CapturedPacket, NetworkCapture
from cap.core import LinkLayerTypes
from cap.pcap import PacketCaptureFormat, PacketCaptureHeaderFormat, CapturedPacketFormat, PacketCaptureFormatDumper, \
    PacketCaptureFormatLoader

__author__ = 'netanelrevah'


def test_initialize_with_defaults():
    packet_capture_header_format = PacketCaptureHeaderFormat()
    packet_capture_format = PacketCaptureFormat(packet_capture_header_format)
    assert packet_capture_format.file_header == packet_capture_header_format
    assert packet_capture_format.captured_packets == []
    assert packet_capture_format.is_big_endian is False


def test_initialize():
    packet_capture_header_format = PacketCaptureHeaderFormat()
    captured_packet_format = CapturedPacketFormat()
    packet_capture_format = PacketCaptureFormat(packet_capture_header_format, [captured_packet_format], True)
    assert packet_capture_format.file_header == packet_capture_header_format
    assert packet_capture_format.captured_packets == [captured_packet_format]
    assert packet_capture_format.is_big_endian is True


def test_initialize_from_network_capture():
    captured_packet = CapturedPacket(b'ABCD')
    network_capture = NetworkCapture([captured_packet])
    packet_capture_format = PacketCaptureFormat.from_network_capture(network_capture)
    assert packet_capture_format.file_header == PacketCaptureHeaderFormat()
    assert packet_capture_format.captured_packets == [CapturedPacketFormat.init_from_captured_packet(captured_packet)]
    assert packet_capture_format.is_big_endian is False


def test_to_network_capture():
    packet_capture_header_format = PacketCaptureHeaderFormat()
    captured_packet_format = CapturedPacketFormat(data=b'ABCD')
    packet_capture_format = PacketCaptureFormat(packet_capture_header_format, [captured_packet_format], True)
    packet_capture_format.file_header.link_layer_type = LinkLayerTypes(0)
    network_capture = packet_capture_format.to_network_capture()
    assert network_capture.captured_packets == [captured_packet_format.to_captured_packet()]
    assert network_capture.environment == LinkLayerTypes(0)


def test_loads():
    CAP_HEADER_WITH_PACKET = BytesIO(b'\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00'
                                     b'\x00\x00\x00\x00U\x0f#D\x00\x0b\xe2\xf8\x00\x00\x00\t\x00\x00\x00\t123456789')
    loader = PacketCaptureFormatLoader(CAP_HEADER_WITH_PACKET)
    packet_capture_format = PacketCaptureFormat(loader.file_header, list(loader), loader.is_big_endian)
    CAP_HEADER_WITH_PACKET.seek(0)
    loaded = PacketCaptureFormat.loads(CAP_HEADER_WITH_PACKET)
    assert loaded.captured_packets == packet_capture_format.captured_packets
    assert loaded.file_header == packet_capture_format.file_header


def test_dumps():
    captured_packet = CapturedPacket(b'ABCD')
    network_capture = NetworkCapture([captured_packet])
    packet_capture_format = PacketCaptureFormat.from_network_capture(network_capture)
    dumper = PacketCaptureFormatDumper(packet_capture_format, packet_capture_format.is_big_endian)
    assert packet_capture_format.dumps() == dumper.file_header + b''.join(list(dumper))

import mock
from cap.pcap import PacketCaptureFormatLoader

__author__ = 'netanelrevah'


def test_initialize_using_defaults():
    mocked_stream = mock.Mock()
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    assert packet_capture_format_loader.stream == mocked_stream
    assert packet_capture_format_loader.is_native_order is False


def test_initialize():
    mocked_stream = mock.Mock()
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream, True)
    assert packet_capture_format_loader.stream == mocked_stream
    assert packet_capture_format_loader.is_native_order is True

from random import randint

from _pytest.python import fixture, raises
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


@fixture
def mocked_stream():
    class MockedStream(object):
        def __init__(self):
            self.streamed = b''
            self.start = b''

        def read(self, size):
            random_string = b''
            if self.start:
                random_string = self.start[:size]
                size -= len(random_string)
            random_string += bytes(bytearray([randint(0, 255) for _ in range(size)]))
            self.streamed += random_string
            return random_string

        def seek(self, pos, configuration):
            pass

    return MockedStream()


def test_file_header_property_with_invalid_magic(mocked_stream):
    mocked_stream.start = b'ABCD'
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream, True)
    with raises(Exception):
        packet_capture_format_loader.file_header


def test_file_header_property_with_valid_magic(mocked_stream):
    mocked_stream.start = list(PacketCaptureFormatLoader.MAGIC_VALUES_TO_ORDER.keys())[0]
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream, True)
    assert packet_capture_format_loader.file_header is not None

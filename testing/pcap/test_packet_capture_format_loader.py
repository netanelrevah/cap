from random import randint

from _pytest.python import fixture, raises
import mock

from cap.pcap import PacketCaptureFormatLoader

__author__ = 'netanelrevah'


def test_initialize():
    mocked_stream = mock.Mock()
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    assert packet_capture_format_loader.stream == mocked_stream
    assert packet_capture_format_loader._is_big_endian is False


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
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    with raises(Exception):
        packet_capture_format_loader.file_header


def test_file_header_property_with_valid_magic(mocked_stream):
    mocked_stream.start = list(PacketCaptureFormatLoader.MAGIC_VALUES_TO_BIG_ENDIAN.keys())[0]
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    assert packet_capture_format_loader.file_header is not None


def test_iteration_builtin():
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    assert iter(packet_capture_format_loader) == packet_capture_format_loader


def test_iteration_with_no_packets():
    # TODO: Replace with random cap creator
    # TODO: Replace with good mocked stream
    CAP_HEADER = b"\xA1\xB2\xC3\xD4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x01"
    def mocked_read(size):
        if size == 4:
            return CAP_HEADER[:4]
        elif size == 24:
            return CAP_HEADER
        return b''
    mocked_stream = mock.Mock()
    mocked_stream.read.side_effect = mocked_read
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    assert list(packet_capture_format_loader) == []

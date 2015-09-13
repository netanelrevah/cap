from io import BytesIO
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


def test_big_endian_property_with_invalid_header():
    CAP_HEADER = b"\xA1\xB2\xC3\x12"
    mocked_stream = MockedStream(BytesIO(CAP_HEADER))
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    with raises(Exception):
        assert packet_capture_format_loader.is_big_endian is not None


def test_big_endian_property_with_little_endian_header():
    CAP_HEADER = b"\xA1\xB2\xC3\xD4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x01"
    mocked_stream = MockedStream(BytesIO(CAP_HEADER))
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    assert packet_capture_format_loader.is_big_endian is False


def test_big_endian_property_with_big_endian_header():
    CAP_HEADER = b"\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
    mocked_stream = MockedStream(BytesIO(CAP_HEADER))
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    assert packet_capture_format_loader.is_big_endian is True


def test_file_header_property_with_invalid_magic(mocked_stream):
    mocked_stream.start = b'ABCD'
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    with raises(Exception):
        assert packet_capture_format_loader.file_header is not None


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
    mocked_stream = MockedStream(BytesIO(CAP_HEADER))
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    assert list(packet_capture_format_loader) == []
    assert mocked_stream.read_params == [(4,), (24,), (16,)]
    assert mocked_stream.seek_params == [(-4, 1)]


class MockedStream(object):
    def __init__(self, stream):
        self.stream = stream
        self.read_params = []
        self.seek_params = []

    def read(self, size):
        self.read_params.append((size,))
        return self.stream.read(size)

    def seek(self, position, configuration):
        self.seek_params.append((position, configuration))
        return self.stream.seek(position, configuration)


def test_iteration_with_one_packets():
    # TODO: Replace with random cap creator
    CAP_HEADER_WITH_PACKET = b'\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00' \
                             b'\x00\x00\x00U\x0f#D\x00\x0b\xe2\xf8\x00\x00\x00\t\x00\x00\x00\t123456789'
    mocked_stream = MockedStream(BytesIO(CAP_HEADER_WITH_PACKET))
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    assert len(list(packet_capture_format_loader)) == 1
    assert mocked_stream.read_params == [(4,), (24,), (16,), (9,), (16,)]
    assert mocked_stream.seek_params == [(-4, 1)]


def test_iteration_with_compatibility():
    # TODO: Replace with random cap creator
    CAP_HEADER_WITH_PACKET = b'\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00' \
                             b'\x00\x00\x00U\x0f#D\x00\x0b\xe2\xf8\x00\x00\x00\t\x00\x00\x00\t123456789'
    mocked_stream = MockedStream(BytesIO(CAP_HEADER_WITH_PACKET))
    packet_capture_format_loader = PacketCaptureFormatLoader(mocked_stream)
    captured_packets = []
    while True:
        try:
            captured_packets.append(packet_capture_format_loader.__next__())
        except StopIteration:
            break

    assert len(captured_packets) == 1
    assert mocked_stream.read_params == [(4,), (24,), (16,), (9,), (16,)]
    assert mocked_stream.seek_params == [(-4, 1)]

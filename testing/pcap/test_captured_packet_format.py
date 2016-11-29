from random import randint

from pytest import fixture, raises

from cap.core import CapturedPacket
from cap._nicer.times import current_datetime
from cap.pcap import CapturedPacketFormat, CapturedPacketHeaderFormat

__author__ = 'netanelrevah'

MOCKED_DATA = b'1234'


def test_init_with_defaults():
    captured_packet_format = CapturedPacketFormat()
    assert captured_packet_format.header == CapturedPacketHeaderFormat()
    assert captured_packet_format.data == b''


def test_init_with_values():
    header = CapturedPacketHeaderFormat(1, 2, 3, 4)
    data = b'ABCD'
    captured_packet_format = CapturedPacketFormat(header, data)
    assert captured_packet_format.header == header
    assert captured_packet_format.data == data


def test_init_from_captured_packet():
    now = current_datetime()
    original_length = len(MOCKED_DATA) + randint(0, 5)
    captured_packet = CapturedPacket(MOCKED_DATA, now, original_length)
    captured_packet_format = CapturedPacketFormat.init_from_captured_packet(captured_packet)
    assert captured_packet_format.header == CapturedPacketHeaderFormat.init_from_captured_packet(captured_packet)
    assert captured_packet_format.data == MOCKED_DATA


def test_to_captured_packet():
    header = CapturedPacketHeaderFormat(1, 2, 4, 3)
    data = b'ABCD'
    captured_packet_format = CapturedPacketFormat(header, data)
    captured_packet = captured_packet_format.to_captured_packet()
    assert captured_packet.data == data
    assert len(captured_packet) == captured_packet_format.header.data_length
    assert captured_packet.capture_time == captured_packet_format.header.capture_time
    assert captured_packet.original_length == captured_packet_format.header.original_length


@fixture
def mocked_stream():
    class MockedStream(object):
        def __init__(self):
            self.streamed = b''
            self.max_length = None

        @staticmethod
        def _generate_word():
            return b'\x00\x00\x00' + bytes(bytearray([randint(0, 255)]))

        def read(self, size):
            if self.max_length is not None:
                size = min(self.max_length, size)
                self.max_length -= size
            if size == 16:
                random_string = b''.join([self._generate_word() for _ in range(4)])
            else:
                random_string = bytes(bytearray([randint(0, 255) for _ in range(size)]))
            self.streamed += random_string
            return random_string

    return MockedStream()


def test_loads_valid_packet(mocked_stream):
    captured_packet_format = CapturedPacketFormat.loads(mocked_stream)
    captured_packet_header_format = CapturedPacketHeaderFormat.unpack(mocked_stream.streamed[0:16])
    assert captured_packet_format.header == captured_packet_header_format
    assert captured_packet_format.data == mocked_stream.streamed[16:]
    assert len(captured_packet_format.data) == captured_packet_header_format.data_length


def test_loads_packet_with_no_data(mocked_stream):
    mocked_stream.max_length = 16
    with raises(Exception):
        CapturedPacketFormat.loads(mocked_stream)


def test_loads_empty_packet(mocked_stream):
    mocked_stream.max_length = 0
    assert CapturedPacketFormat.loads(mocked_stream) is None


def test_dumps():
    header = CapturedPacketHeaderFormat(1, 2, 3, 4)
    data = b'ABCD'
    captured_packet_format = CapturedPacketFormat(header, data)
    assert captured_packet_format.dumps() == header.pack() + data

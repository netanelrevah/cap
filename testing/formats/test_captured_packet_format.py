from random import randint
from _pytest.python import fixture
import mock

from cap.formats import CapturedPacketFormat, CapturedPacketHeaderFormat
from cap.logics import CapturedPacket
from cap.nicer.times import current_datetime

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

        def read(self, size):
            if size == 16:
                random_string = bytes(bytearray([i for i in [0, 0, 0, randint(0, 255)] for _ in range(4)]))
            else:
                random_string = bytes(bytearray(randint(0, 5) for _ in range(size)))
            self.streamed += random_string
            return random_string

    return MockedStream()


def test_loads_valid_packet(mocked_stream):
    captured_packet_format = CapturedPacketFormat.loads(mocked_stream)
    captured_packet_header_format = CapturedPacketHeaderFormat.unpack(mocked_stream.streamed[0:16])
    assert captured_packet_format.header == captured_packet_header_format
    assert captured_packet_format.data == mocked_stream.streamed[16:]
    assert len(captured_packet_format.data) == captured_packet_header_format.data_length

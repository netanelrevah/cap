from datetime import datetime
import binascii
from random import randint
from cap.core import CapturedPacket
from cap.nicer.bits import format_byte
from cap.nicer.times import current_datetime, datetime_from_timestamp

__author__ = 'netanelrevah'

MOCKED_DATA = b'Some Mocked Data'


def test_initialize_with_defaults():
    time_before = current_datetime()
    captured_packet = CapturedPacket(MOCKED_DATA)
    time_after = current_datetime()
    assert captured_packet.data == MOCKED_DATA
    assert time_before <= captured_packet.capture_time <= time_after
    assert captured_packet.original_length == len(MOCKED_DATA)


def test_initialize_with_values():
    captured_packet = CapturedPacket(MOCKED_DATA, datetime(2000, 2, 20), len(MOCKED_DATA) + 4)
    assert captured_packet.data == MOCKED_DATA
    assert captured_packet.capture_time == datetime(2000, 2, 20)
    assert captured_packet.original_length == len(MOCKED_DATA) + 4


def test_initialize_with_timestamp():
    captured_packet = CapturedPacket(MOCKED_DATA, 123)
    assert captured_packet.capture_time == datetime_from_timestamp(123)


def test_copy():
    captured_packet = CapturedPacket(MOCKED_DATA, datetime(2000, 2, 20), len(MOCKED_DATA) + 4)
    copied = captured_packet.copy()
    assert captured_packet == copied
    assert id(captured_packet) != id(copied)


def test_is_fully_captured_property():
    captured_packet = CapturedPacket(MOCKED_DATA, original_length=len(MOCKED_DATA))
    assert captured_packet.is_fully_captured
    captured_packet = CapturedPacket(MOCKED_DATA, original_length=len(MOCKED_DATA) + 4)
    assert not captured_packet.is_fully_captured


def test_equality():
    captured_packet = CapturedPacket(MOCKED_DATA, datetime(2000, 2, 20), len(MOCKED_DATA) + 4)
    other_captured_packet = CapturedPacket(MOCKED_DATA + b'a', datetime(2002, 3, 23), len(MOCKED_DATA) + 7)
    assert captured_packet != other_captured_packet
    other_captured_packet.data = MOCKED_DATA
    assert captured_packet != other_captured_packet
    other_captured_packet.capture_time = datetime(2000, 2, 20)
    assert captured_packet != other_captured_packet
    other_captured_packet.original_length = len(MOCKED_DATA) + 4
    assert captured_packet == other_captured_packet


def test_str():
    captured_packet = CapturedPacket(MOCKED_DATA)
    assert str(captured_packet) == binascii.hexlify(MOCKED_DATA).decode('ascii')


def test_iter():
    captured_packet = CapturedPacket(MOCKED_DATA)
    assert MOCKED_DATA == bytes(bytearray([b for b in captured_packet]))


def test_index():
    captured_packet = CapturedPacket(MOCKED_DATA)
    randomized_index = randint(0, len(MOCKED_DATA) - 1)
    assert MOCKED_DATA[randomized_index] == captured_packet[randomized_index]

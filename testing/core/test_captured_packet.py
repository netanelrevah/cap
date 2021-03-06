import binascii
from datetime import datetime
from random import randint
from unittest.mock import patch, Mock

import pytest

from nicer.times import Timestamp
from pkt.captures import CapturedPacket

__author__ = 'netanelrevah'

MOCKED_DATA = b'Some Mocked Data'


@patch('nicer.times.Timestamp.now')
def test_initialize_with_default_parameters(timestamp_now):  # type: (Mock) -> None
    captured_packet = CapturedPacket(MOCKED_DATA)
    assert captured_packet.data == MOCKED_DATA
    timestamp_now.assert_called_once_with()
    assert captured_packet.original_length == len(MOCKED_DATA)


def test_initialize_with_values():
    captured_packet = CapturedPacket(MOCKED_DATA, Timestamp(42, 6 * 9), len(MOCKED_DATA) + 4)
    assert captured_packet.data == MOCKED_DATA
    assert captured_packet.capture_time == Timestamp(42, 6 * 9)
    assert captured_packet.original_length == len(MOCKED_DATA) + 4


def test_initialize_with_timestamp():
    captured_packet = CapturedPacket(MOCKED_DATA, 123)
    assert captured_packet.capture_time == Timestamp(123)


@pytest.mark.skip
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
    captured_packet = CapturedPacket(MOCKED_DATA, Timestamp(2000, 2), len(MOCKED_DATA) + 4)
    other_captured_packet = CapturedPacket(MOCKED_DATA + b'a', Timestamp(2002, 3), len(MOCKED_DATA) + 7)
    assert captured_packet != other_captured_packet
    other_captured_packet.data = MOCKED_DATA
    assert captured_packet != other_captured_packet
    other_captured_packet.capture_time = Timestamp(2000, 2)
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

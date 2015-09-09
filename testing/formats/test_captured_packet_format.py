from random import randint

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

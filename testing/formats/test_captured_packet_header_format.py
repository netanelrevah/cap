from datetime import datetime
from random import randint
import struct

import mock

from _pytest.python import raises
import pytz

from cap.formats import CapturedPacketHeaderFormat
from cap.logics import CapturedPacket
from cap.nicer.times import seconds_from_datetime, current_datetime

MOCKED_DATA = b'SomeRandomStringOfData'

__author__ = 'netanelrevah'


def test_init_with_defaults():
    captured_packet_header_format = CapturedPacketHeaderFormat()
    assert captured_packet_header_format.seconds == 0
    assert captured_packet_header_format.microseconds == 0
    assert captured_packet_header_format.data_length == 0
    assert captured_packet_header_format.original_length == 0


def test_init_with_randoms():
    seconds = randint(0, 100)
    microseconds = randint(0, 100)
    data_length = randint(0, 100)
    original_length = randint(0, 100)
    captured_packet_header_format = CapturedPacketHeaderFormat(seconds, microseconds, data_length, original_length)
    assert captured_packet_header_format.seconds == seconds
    assert captured_packet_header_format.microseconds == microseconds
    assert captured_packet_header_format.data_length == data_length
    assert captured_packet_header_format.original_length == original_length


def test_eq():
    seconds = randint(0, 100)
    microseconds = randint(0, 100)
    data_length = randint(0, 100)
    original_length = randint(0, 100)
    captured_packet_header_format1 = CapturedPacketHeaderFormat(seconds, microseconds, data_length, original_length)
    captured_packet_header_format2 = CapturedPacketHeaderFormat()
    assert captured_packet_header_format1 != captured_packet_header_format2
    captured_packet_header_format2.seconds = seconds
    assert captured_packet_header_format1 != captured_packet_header_format2
    captured_packet_header_format2.microseconds = microseconds
    assert captured_packet_header_format1 != captured_packet_header_format2
    captured_packet_header_format2.data_length = data_length
    assert captured_packet_header_format1 != captured_packet_header_format2
    captured_packet_header_format2.original_length = original_length
    assert captured_packet_header_format1 == captured_packet_header_format2


def test_capture_time_property_for_epoch():
    captured_packet_header_format = CapturedPacketHeaderFormat()
    assert captured_packet_header_format.capture_time == datetime(1970, 1, 1, tzinfo=pytz.UTC)


def test_capture_time_property_for_now():
    now = current_datetime()
    captured_packet_header_format = CapturedPacketHeaderFormat(seconds_from_datetime(now), now.microsecond)
    assert captured_packet_header_format.capture_time == now


# def test_pack_with_randoms():
#     seconds = randint(0x00, 0xFFFFFFFF)
#     microseconds = randint(0x00, 0xFFFFFFFF)
#     data_length = randint(0x00, 0xFFFFFFFF)
#     original_length = randint(0x00, 0xFFFFFFFF)
#     captured_packet_header_format = CapturedPacketHeaderFormat(seconds, microseconds, data_length, original_length)
#     assert captured_packet_header_format.pack(True) == struct.pack(
#         '<IIII', seconds, microseconds, data_length, original_length)
#
#
# def test_pack_with_randoms_and_big_endian():
#     seconds = randint(0x00, 0xFFFFFFFF)
#     microseconds = randint(0x00, 0xFFFFFFFF)
#     data_length = randint(0x00, 0xFFFFFFFF)
#     original_length = randint(0x00, 0xFFFFFFFF)
#     captured_packet_header_format = CapturedPacketHeaderFormat(seconds, microseconds, data_length, original_length)
#     assert captured_packet_header_format.pack(False) == struct.pack(
#         '>IIII', seconds, microseconds, data_length, original_length)


def test_init_from_captured_packet():
    now = datetime.now(tz=pytz.UTC)
    original_length = len(MOCKED_DATA) + randint(0, 100)
    captured_packet = CapturedPacket(MOCKED_DATA, now, original_length)
    captured_packet_header_format = CapturedPacketHeaderFormat.init_from_captured_packet(captured_packet)
    assert captured_packet_header_format.seconds == seconds_from_datetime(now)
    assert captured_packet_header_format.microseconds == now.microsecond
    assert captured_packet_header_format.data_length == len(MOCKED_DATA)
    assert captured_packet_header_format.original_length == original_length


def test_loads():
    seconds = randint(0x00, 0xFFFFFFFF)
    microseconds = randint(0x00, 0xFFFFFFFF)
    data_length = randint(0x00, 0xFFFFFFFF)
    original_length = randint(0x00, 0xFFFFFFFF)
    captured_packet_header_format = CapturedPacketHeaderFormat(seconds, microseconds, data_length, original_length)

    stream = mock.Mock()
    stream.read.return_value = captured_packet_header_format.pack()
    loaded_captured_packet_header_format = CapturedPacketHeaderFormat.loads(stream)
    assert loaded_captured_packet_header_format.seconds == seconds
    assert loaded_captured_packet_header_format.microseconds == microseconds
    assert loaded_captured_packet_header_format.data_length == data_length
    assert loaded_captured_packet_header_format.original_length == original_length


def test_loads_with_none_value():
    stream = mock.Mock()
    stream.read.return_value = None
    assert CapturedPacketHeaderFormat.loads(stream) is None


def test_loads_with_empty_value():
    stream = mock.Mock()
    stream.read.return_value = b''
    assert CapturedPacketHeaderFormat.loads(stream) is None


def test_loads_with_insufficient_length():
    stream = mock.Mock()
    stream.read.return_value = b'AB'
    with raises(struct.error):
        CapturedPacketHeaderFormat.loads(stream)

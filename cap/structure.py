from cap.nicer.structs import DefinedStruct

__author__ = 'netanelrevah'

from struct import Struct
from cap.nicer.times import datetime_from_seconds_and_microseconds


class CapturedPacketHeaderStruct(DefinedStruct):
    NATIVE_ORDER_HEADER_STRUCT = Struct('>IIII')
    SWAPPED_ORDER_HEADER_STRUCT = Struct('<IIII')

    def __init__(self, seconds, microseconds, data_length, original_length):
        self.seconds = seconds
        self.microseconds = microseconds
        self.data_length = data_length
        self.original_length = original_length

    @property
    def capture_time(self):
        return datetime_from_seconds_and_microseconds(self.seconds, self.microseconds)

    def _get_values_tuple(self):
        return (self.seconds,
                self.microseconds,
                self.data_length,
                self.original_length)


class NetworkCaptureHeaderStruct(DefinedStruct):
    NATIVE_ORDER_HEADER_STRUCT = Struct('>IHHiIII')
    SWAPPED_ORDER_HEADER_STRUCT = Struct('<IHHiIII')

    MAGIC_VALUE = 0xa1b2c3d4

    def __init__(self, major_version, minor_version, time_zone_hours, max_capture_length_octets, link_layer_type):
        self.major_version = major_version
        self.minor_version = minor_version
        self.time_zone_hours = time_zone_hours
        self.max_capture_length_octets = max_capture_length_octets
        self.link_layer_type = link_layer_type

    @staticmethod
    def _filter_constants(values):
        return values[1], values[2], values[4], values[5], values[6]

    def _get_values_tuple(self):
        return self.MAGIC_VALUE, self.major_version, self.minor_version, self.time_zone_hours, 0, \
            self.max_capture_length_octets, self.link_layer_type


class CapturedPacketSection(object):
    def __init__(self):
        self.header = None
        self.data = None
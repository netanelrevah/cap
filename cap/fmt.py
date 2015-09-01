__author__ = 'netanelrevah'

from struct import Struct
from cap.nicer.times import datetime_from_seconds_and_microseconds


class DefinedStruct(object):
    NATIVE_ORDER_HEADER_STRUCT = None
    SWAPPED_ORDER_HEADER_STRUCT = None

    @classmethod
    def get_struct(cls, is_native_order=True):
        return cls.NATIVE_ORDER_HEADER_STRUCT if is_native_order else cls.SWAPPED_ORDER_HEADER_STRUCT

    def _get_values_tuple(self):
        raise NotImplementedError()

    def pack(self, is_native_order=True):
        return self.get_struct(is_native_order).pack(*self._get_values_tuple())

    @classmethod
    def unpack(cls, data, is_native_order=True):
        header_struct = cls.get_struct(is_native_order)
        return cls(*header_struct.unpack(data))


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

    def __init__(self, magic, major_version, minor_version, time_zone_hours, what, max_capture_length_octets,
                 link_layer_type):
        self.magic = magic
        self.major_version = major_version
        self.minor_version = minor_version
        self.time_zone_hours = time_zone_hours
        self.max_capture_length_octets = max_capture_length_octets
        self.link_layer_type = link_layer_type

    def _get_values_tuple(self):
        return (self.magic,
                self.major_version,
                self.minor_version,
                self.time_zone_hours,
                0,
                self.max_capture_length_octets,
                self.link_layer_type)

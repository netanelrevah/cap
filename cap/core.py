from enum import Enum
import binascii

from cap.nicer.bits import format_bytes
from cap.nicer.times import current_datetime, datetime_from_timestamp
from pkt import Packet

__author__ = 'netanelrevah'


class LinkLayerTypes(Enum):
    none, ethernet = tuple(range(0, 2))


class NetworkCapture(object):
    def __init__(self, captured_packets=None, link_layer_type=LinkLayerTypes.ethernet):
        self.link_layer_type = LinkLayerTypes(link_layer_type)
        self.captured_packets = captured_packets if captured_packets is not None else []

    def copy(self):
        copied_packets = [p.copy() for p in self.captured_packets]
        return NetworkCapture(copied_packets, self.link_layer_type)

    def __add__(self, other):
        if self.link_layer_type != other.link_layer_type:
            raise TypeError("Can't add network capture with different link layer type!")
        return NetworkCapture([p.copy() for p in self.captured_packets + other.captured_packets], self.link_layer_type)

    def __len__(self):
        return len(self.captured_packets)

    def __getitem__(self, index):
        return self.captured_packets[index]

    def __iter__(self):
        return self.captured_packets.__iter__()

    def __repr__(self):  # pragma: no cover
        if len(self) == 0:
            return '<NetworkCapture - Empty>'
        return '<CaptureFile - {} packets from {} to {}>'.format(len(self), self[0].capture_time, self[-1].capture_time)

    def append(self, packet):
        self.captured_packets.append(packet)

    def sort(self, key=lambda p: p.capture_time):
        self.captured_packets.sort(key=key)


class CapturedPacket(Packet):
    def __init__(self, data, capture_time=None, original_length=None):
        super(CapturedPacket, self).__init__(data)

        self.capture_time = capture_time
        if self.capture_time is None:
            self.capture_time = current_datetime()
        elif isinstance(self.capture_time, int) or isinstance(self.capture_time, float):
            self.capture_time = datetime_from_timestamp(self.capture_time)

        self.original_length = original_length
        if self.original_length is None:
            self.original_length = len(data)

    def copy(self):
        return CapturedPacket(self.data, self.capture_time, self.original_length)

    @property
    def is_fully_captured(self):
        return self.original_length == len(self)

    def __repr__(self):
        return '<CapturedPacket - %d bytes captured at %s >' % (len(self.data), self.capture_time)

    def to_immutable(self):
        return self.data, self.capture_time, self.original_length

from enum import Enum

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

    def __repr__(self):
        if len(self) == 0:
            return '<NetworkCapture - Empty>'
        return '<CaptureFile - {} packets from {} to {}>'.format(len(self), self[0].capture_time, self[-1].capture_time)

    def append(self, packet):
        self.captured_packets.append(packet)

    def sort(self, key=lambda p: p.capture_time):
        self.captured_packets.sort(key=key)

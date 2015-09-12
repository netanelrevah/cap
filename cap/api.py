from cap.core import NetworkCapture
from cap.pcap import PacketCaptureFormat
from cap.nicer.streams import to_stream

__author__ = 'netanelrevah'


def load(path):
    return loads(open(path, 'rb'))


def loads(stream):
    return PacketCaptureFormat.loads(to_stream(stream)).to_network_capture()


def dump(network_capture, path, major_version=2, minor_version=4, time_zone_hours=0, max_capture_length_octets=0x40000,
         link_layer_type=1, is_native_order=True):
    open(path, 'wb').write(dumps(network_capture, major_version, minor_version, time_zone_hours,
                                 max_capture_length_octets, link_layer_type, is_native_order))


def dumps(network_capture, major_version=2, minor_version=4, time_zone_hours=0, max_capture_length_octets=0x40000,
          link_layer_type=1, is_native_order=True):
    packet_capture_format = PacketCaptureFormat.from_network_capture(network_capture)
    packet_capture_format.file_header.major_version = major_version
    packet_capture_format.file_header.minor_version = minor_version
    packet_capture_format.file_header.time_zone_hours = time_zone_hours
    packet_capture_format.file_header.max_capture_length_octets = max_capture_length_octets
    packet_capture_format.file_header.link_layer_type = link_layer_type
    packet_capture_format.is_native_order = is_native_order
    return packet_capture_format.dumps()


def merge(target_path, *source_paths):
    result = NetworkCapture()
    for source_path in source_paths:
        result.append(load(source_path))
    return dump(result, target_path)

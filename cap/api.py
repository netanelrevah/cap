from .core import NetworkCapture
from ._nicer.streams import to_stream
from .pcap import PacketCaptureFormat, PacketCaptureFormatLoader, PacketCaptureFormatDumper

__author__ = 'netanelrevah'


def load(path):
    return load_from_file(path)


def load_from_file(path):
    return load_from_stream(open(path, 'rb'))


def load_from_stream(stream):
    return PacketCaptureFormat.loads(to_stream(stream)).to_network_capture()


def loads(stream):
    return load_from_stream(stream)


def loader(stream):
    return PacketCaptureFormatLoader(to_stream(stream))


def dump_into_file(network_capture, path, major_version=2, minor_version=4, time_zone_hours=0,
                   max_capture_length_octets=0x40000,
                   link_layer_type=1, is_big_endian=False):
    open(path, 'wb').write(dump_into_bytes(network_capture, major_version, minor_version, time_zone_hours,
                                           max_capture_length_octets, link_layer_type, is_big_endian))


def dump_into_bytes(network_capture,
                    major_version=2, minor_version=4, time_zone_hours=0, max_capture_length_octets=0x40000,
                    link_layer_type=1, is_big_endian=False):
    packet_capture_format = PacketCaptureFormat.from_network_capture(network_capture)
    packet_capture_format.file_header.major_version = major_version
    packet_capture_format.file_header.minor_version = minor_version
    packet_capture_format.file_header.time_zone_hours = time_zone_hours
    packet_capture_format.file_header.max_capture_length_octets = max_capture_length_octets
    packet_capture_format.file_header.link_layer_type = link_layer_type
    packet_capture_format.is_native_order = is_big_endian
    return packet_capture_format.dumps()


def dump(network_capture, path,
         major_version=2, minor_version=4, time_zone_hours=0, max_capture_length_octets=0x40000, link_layer_type=1,
         is_big_endian=False):
    return dump_into_file(network_capture, path,
                          major_version, minor_version, time_zone_hours, max_capture_length_octets, link_layer_type,
                          is_big_endian)


def dumps(network_capture,
          major_version=2, minor_version=4, time_zone_hours=0, max_capture_length_octets=0x40000,
          link_layer_type=1, is_big_endian=False):
    dump_into_bytes(network_capture,
                    major_version, minor_version, time_zone_hours, max_capture_length_octets, link_layer_type,
                    is_big_endian)


def dumper(stream):
    return PacketCaptureFormatDumper(to_stream(stream))


def merge(target_path, *source_paths):
    result = NetworkCapture()
    for source_path in source_paths:
        result.append(load(source_path))
    return dump_into_file(result, target_path)

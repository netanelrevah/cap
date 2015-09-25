from random import randint
from _pytest.python import raises
import mock
from cap.core import NetworkCapture, LinkLayerTypes

__author__ = 'netanelrevah'


def test_initialize_with_defaults():
    network_capture = NetworkCapture()
    assert network_capture.link_layer_type == LinkLayerTypes.ethernet
    assert network_capture.captured_packets == []


def test_initialize_with_values():
    captured_packet = mock.Mock()
    network_capture = NetworkCapture([captured_packet], LinkLayerTypes.none)
    assert network_capture.link_layer_type == LinkLayerTypes.none
    assert network_capture.captured_packets == [captured_packet]


def test_copy():
    captured_packet = mock.Mock()
    network_capture = NetworkCapture([captured_packet], LinkLayerTypes.none)
    copied_network_capture = network_capture.copy()
    assert captured_packet.copy.call_count == 1
    assert id(copied_network_capture) != id(network_capture)
    assert copied_network_capture.link_layer_type == LinkLayerTypes.none


def test_add():
    first_captured_packet = mock.Mock()
    first_captured_packet.copy.return_value = first_captured_packet
    first_network_capture = NetworkCapture([first_captured_packet], LinkLayerTypes.none)
    second_captured_packet = mock.Mock()
    second_captured_packet.copy.return_value = second_captured_packet
    second_network_capture = NetworkCapture([second_captured_packet], LinkLayerTypes.none)
    merged = first_network_capture + second_network_capture
    assert merged.captured_packets == [first_captured_packet, second_captured_packet]
    assert merged.link_layer_type == LinkLayerTypes.none


def test_add_other_link_layer_type_failed():
    first_captured_packet = mock.Mock()
    first_captured_packet.copy.return_value = first_captured_packet
    first_network_capture = NetworkCapture([first_captured_packet], LinkLayerTypes.none)
    second_network_capture = NetworkCapture(link_layer_type=LinkLayerTypes.ethernet)
    with raises(Exception):
        first_network_capture + second_network_capture


def test_length():
    randomized_length = randint(0, 40)
    mocked_captured_packet_list = range(randomized_length)
    first_network_capture = NetworkCapture(mocked_captured_packet_list)
    assert len(first_network_capture) == randomized_length


def test_index():
    randomized_length = randint(0, 40)
    mocked_captured_packet_list = range(randomized_length)
    first_network_capture = NetworkCapture(mocked_captured_packet_list)
    randomized_index = randint(0, randomized_length - 1)
    assert first_network_capture[randomized_index] == mocked_captured_packet_list[randomized_index]


def test_append():
    first_captured_packet = mock.Mock()
    network_capture = NetworkCapture([first_captured_packet], LinkLayerTypes.none)
    second_captured_packet = mock.Mock()

    network_capture.append(second_captured_packet)
    assert network_capture.captured_packets == [first_captured_packet, second_captured_packet]


def test_sort():
    mocked_captured_packet_list = mock.Mock()
    network_capture = NetworkCapture(mocked_captured_packet_list)
    mocked_key = mock.Mock()
    network_capture.sort(mocked_key)
    mocked_captured_packet_list.sort.assert_called_once_with(key=mocked_key)

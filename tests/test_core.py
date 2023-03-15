from cap import SecondsPartsUnit
from cap.core import Timestamp


def test_timestamp_equality():
    t1 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)
    t2 = Timestamp(10, 111111000, seconds_parts_unit=SecondsPartsUnit.nanos)

    assert t1 == t2
    assert t2 == t1

    t1 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)
    t2 = Timestamp(10, 111111001, seconds_parts_unit=SecondsPartsUnit.nanos)

    assert t1 != t2
    assert t2 != t1

    t1 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)
    t2 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)

    assert t1 == t2
    assert t2 == t1

    t1 = Timestamp(10, 111112, seconds_parts_unit=SecondsPartsUnit.micros)
    t2 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)

    assert t1 != t2
    assert t2 != t1


def test_timestamp_comparability():
    t1 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)
    t2 = Timestamp(10, 111111000, seconds_parts_unit=SecondsPartsUnit.nanos)

    assert t1 <= t2
    assert t2 >= t1

    t1 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)
    t2 = Timestamp(10, 111111001, seconds_parts_unit=SecondsPartsUnit.nanos)

    assert t1 < t2
    assert t2 > t1

    t1 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)
    t2 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)

    assert t1 <= t2
    assert t2 >= t1

    t1 = Timestamp(10, 111112, seconds_parts_unit=SecondsPartsUnit.micros)
    t2 = Timestamp(10, 111111, seconds_parts_unit=SecondsPartsUnit.micros)

    assert t1 > t2
    assert t2 < t1

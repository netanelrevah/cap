__author__ = 'code-museum'

from datetime import datetime, timedelta
import time


def current_datetime():
    return datetime.now()


def seconds_from_datetime(value):
    """
    :type value: datetime
    """
    return int(time.mktime(value.timetuple()))


def microseconds_from_datetime(value):
    """
    :type value: datetime
    """
    return value.microsecond


def datetime_from_timestamp(value):
    return datetime.fromtimestamp(value)


def datetime_from_seconds_and_microseconds(seconds, microseconds):
    return datetime.fromtimestamp(seconds) + timedelta(microseconds=microseconds)

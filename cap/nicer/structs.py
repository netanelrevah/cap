__author__ = 'netanelrevah'


class DefinedStruct(object):
    LITTLE_ENDIAN_HEADER_STRUCT = None
    BIG_ENDIAN_HEADER_STRUCT = None

    @classmethod
    def get_struct(cls, is_big_endian=False):
        return cls.LITTLE_ENDIAN_HEADER_STRUCT if is_big_endian else cls.BIG_ENDIAN_HEADER_STRUCT

    @staticmethod
    def _filter_constants(values):
        return values

    def _get_values_tuple(self):
        raise NotImplementedError()

    def pack(self, is_big_endian=False):
        return self.get_struct(is_big_endian).pack(*self._get_values_tuple())

    @classmethod
    def unpack(cls, data, is_big_endian=False):
        header_struct = cls.get_struct(is_big_endian)
        return cls(*cls._filter_constants(header_struct.unpack(data)))

    @classmethod
    def size(cls):
        return cls.LITTLE_ENDIAN_HEADER_STRUCT.size

    def __eq__(self, other):
        return self._get_values_tuple() == other._get_values_tuple()

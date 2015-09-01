__author__ = 'netanelrevah'


class DefinedStruct(object):
    NATIVE_ORDER_HEADER_STRUCT = None
    SWAPPED_ORDER_HEADER_STRUCT = None

    @classmethod
    def get_struct(cls, is_native_order=True):
        return cls.NATIVE_ORDER_HEADER_STRUCT if is_native_order else cls.SWAPPED_ORDER_HEADER_STRUCT

    @staticmethod
    def _filter_constants(values):
        return values

    def _get_values_tuple(self):
        raise NotImplementedError()

    def pack(self, is_native_order=True):
        return self.get_struct(is_native_order).pack(*self._get_values_tuple())

    @classmethod
    def unpack(cls, data, is_native_order=True):
        header_struct = cls.get_struct(is_native_order)
        return cls(*cls._filter_constants(header_struct.unpack(data)))
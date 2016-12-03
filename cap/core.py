from enum import Enum

__author__ = 'netanelrevah'


class LinkLayerTypes(Enum):
    none, ethernet = tuple(range(0, 2))

import abc
from abc import ABC
from enum import Enum


class ITranslator(ABC):
    """

    """
    def __init__(self, mapping, io):
        self._io = io
        self.set_mapping(mapping)
        self._virtual_subnets = None

    def set_mapping(self, mapping):
        """
        Set incoming mapping and reverse it if
        :param mapping:
        """
        if mapping is None:
            self._mapping = None
        else:
            if self._io == IO.INPUT:
                self._mapping = mapping
            else:
                self._mapping = {v: k for k, v in mapping.items()}
        self.mapping_changed()

    @abc.abstractmethod
    def mapping_changed(self):
        """
        Can be implemented to receive a notifivation method call if the mapping has changed
        """
        pass

    def set_virtual_subnets(self, v_subnets):
        self._virtual_subnets = v_subnets


class IO(Enum):
    INPUT = 0
    OUTPUT = 1

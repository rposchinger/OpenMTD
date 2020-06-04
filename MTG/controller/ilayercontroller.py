import abc

from controller.itranslator import ITranslator


class ILayerController(ITranslator):
    @abc.abstractmethod
    def process_packet(self, packet):
        """
        Return true if packet should be redirected
        Return false if packet should be dropped
        :rtype: Boolean
        :param packet: IP/Ipv6 Scapy Package
        """
        pass
    
    @abc.abstractmethod
    def layers(self):
        """
        :rtype: list of layers

        """
        pass

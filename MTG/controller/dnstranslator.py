

from scapy.layers.dns import DNSRR, DNS

from InternalLogger.internallogger import InternalLogger
from controller.ilayercontroller import ILayerController
from controller.itranslator import IO


class DnsTranslator(ILayerController):
    """

    """
    def layers(self):
        """

        :return: list of layers translated by this controller
        (DNS Ressource Record)
        """
        return [DNSRR]

    def __init__(self, mapping, ttl):
        super().__init__(mapping, IO.OUTPUT)
        self._ttl = ttl

    def process_packet(self, packet):
        """

        :param packet: IPv4 / IPv6 packet
        :return: forward?
        """
        InternalLogger.get().debug("DNS Controller processing packet...")
        # .show() = all layer informations
        #Check if it has the DNSRR Layer
        if packet.haslayer(DNSRR):
            #Extract Data

            #resource IP
            rdata = packet[DNSRR].rdata
            #resource Name (Domain)
            rrname = packet[DNSRR].rrname
            dns_type = packet[DNSRR].type
            if self._mapping is not None:
                new_ip = self._mapping.get(rdata)
                if new_ip is not None:
                    #vIP found in Mapping
                    InternalLogger.get().debug("DNS Response IP Replaced for " + str(rrname)
                                       + "; new = " + str(new_ip) + "; old = "
                                       + str(rdata))
                    #create new response and add it to the existing packet
                    dns_response = DNSRR(rrname=rrname, rdata=new_ip, type=dns_type, ttl=self._ttl)
                    packet[DNS].an = dns_response
                    #change answer count
                    packet[DNS].ancount = 1
            else:
                InternalLogger.get().error("DNS Mapping is None")
        else:
            InternalLogger.get().error("No DNSRR Layer (Translator)")
        return True

    def mapping_changed(self):
        """
        #Not used
        """
        pass

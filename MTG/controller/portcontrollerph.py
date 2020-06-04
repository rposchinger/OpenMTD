from netaddr import IPNetwork
from scapy.layers.inet import TCP, UDP

from InternalLogger.internallogger import InternalLogger
from controller.helper.networkhelper import NetworkHelper
from controller.ilayercontroller import ILayerController
from controller.itranslator import IO


class PortTranslatorPh(ILayerController):
    """
    Port Controller ( Port Hopping )
    """
    def layers(self):
        """
        :return: list of layers translated by this controller
        """
        return [TCP, UDP]

    def __init__(self, ph_function, io, whitelist, client, keymap, ph_subnet_server):
        """

        :param ph_function: Port Hopping Function (IPHFunction)
        :param io: Input or Output
        :param whitelist: Whitelist (Ips)
        :param client: Is this Host part of the client network?
        :param keymap: Map of IPs to PSKs
        """
        super().__init__(None, io)
        self._ph_function = ph_function
        self._io = io
        self._whitelist = whitelist
        self._client = client
        self._keymap = keymap
        self._network_helper = NetworkHelper()
        self._ph_subnet_server = ph_subnet_server

    def process_packet(self, packet):
        """
        Forward the packet to the translator if necessary

        :param packet: IPv4/IPv6 Packet with TCP or UDP Payload
        :return: forward?
        """
        #check if source or dst ip is in ph_subnet_server list
        is_not_in_sever_subnet = False
        for subnet in self._ph_subnet_server:
            netw = IPNetwork(subnet)
            if not (packet.dst in netw or packet.src in netw):
                is_not_in_sever_subnet = True
        if is_not_in_sever_subnet:
            InternalLogger.get().debug("PH: Forwarding the incoming packet, not a connection to a MTD Host")

        #check if source or dst ip is in whitelist (for incoming and leaving packets)
        is_whitelist = False
        for whitelist_address in self._whitelist:
            netw = IPNetwork(whitelist_address)
            if packet.dst in netw or packet.src in netw:
                is_whitelist = True
                break

        if is_whitelist:
            InternalLogger.get().debug("PH: Forwarding the incoming packet, no MTD Host and in whitelist")
        #check if destination is this host (local address)
        elif packet.dst in self._network_helper.local_addresses():
            InternalLogger.get().debug("PH: Accepting the incoming packet, destination = local address")
        else:
            #translate ports
            return self._translate(packet)
        return True

    def _translate(self, packet):
        """
        Translate ports

        :param packet: IPv4/IPv6 Packet with TCP or UDP Payload
        :return: forward?
        """
        InternalLogger.get().debug("Trying to translate port...")
        #check if packet has TCP or UDP payload and extract it
        tcp_or_udp = None
        if packet.haslayer(TCP):
            tcp_or_udp = packet[TCP]
        if packet.haslayer(UDP):
            tcp_or_udp = packet[UDP]
        if tcp_or_udp is None:
            InternalLogger.get().error("ERROR: No TCP or UDP Layer found")
            return True     #Internal Error? Forward Anyways

        new_port = None
        #Translate incoming packets
        if self._io == IO.INPUT:
            if self._client:
                #Gateway is part of the client network
                ip = packet.dst
                key = self._keymap.get(ip)
                if key is None:
                    # No key, drop packet
                    InternalLogger.get().debug("No key for " + ip)
                    return False
                old_port = tcp_or_udp.sport
                new_port = self._ph_function.virtual_port_to_rport(old_port, ip, key)
                tcp_or_udp.sport = new_port
            else:
                # Gateway is part of the host network
                ip = packet.src
                key = self._keymap.get(ip)
                if key is None:
                    # No key, drop packet
                    InternalLogger.get().debug("No key for " + ip)
                    return False
                old_port = tcp_or_udp.dport
                new_port = self._ph_function.virtual_port_to_rport(old_port, ip, key)
                tcp_or_udp.dport = new_port
        else:
        #Translate leaving packets
            if self._client:
                # Gateway is part of the client network
                ip = packet.src
                key = self._keymap.get(ip)
                if key is None:
                    # No key, drop packet
                    InternalLogger.get().debug("No key for " + ip)
                    return False
                old_port = tcp_or_udp.dport
                new_port = self._ph_function.real_port_to_vport(old_port, ip, key)
                tcp_or_udp.dport = new_port
            else:
                # Gateway is part of the host network
                ip = packet.dst
                key = self._keymap.get(ip)
                if key is None:
                    InternalLogger.get().debug("No key for " + ip)
                    #No key, drop packet
                    return False
                old_port = tcp_or_udp.sport
                new_port = self._ph_function.real_port_to_vport(old_port, ip, key)
                tcp_or_udp.sport = new_port

        if new_port is None:
            InternalLogger.get().error("Error no rPort found")
            return
        InternalLogger.get().debug("Old Port = " + str(old_port))
        InternalLogger.get().debug("New Port = " + str(new_port))
        return True

    def mapping_changed(self):
        """
        Not used, no mapping required
        """
        pass


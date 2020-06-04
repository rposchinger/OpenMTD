import abc


class IConnectionTracker():
    @abc.abstractmethod
    def track_connection(self, packet, io):
        """
        :param io: Packet incoming or leaving?
        :param packet: IP/Ipv6 Scapy Package
        """
        pass

    @abc.abstractmethod
    def add_connection(self, sourceIP, sourcePort, dest_vIP, dest_rPort, dest_rIP, enforce):
        """
        Add connection information for connection which should be generated in other components

        :param sourcePort: Source Port
        :param sourceIP: Source IP-Address
        :param dest_rPort: Destination virtual Port
        :param dest_vIP:  Destination virtual IP-Address
        :param dest_rIP: Destination real IP-Address
        :param enforce: Tell other modules that this connection should be kept alive (even if other security measures prohibit it)
        """
        pass
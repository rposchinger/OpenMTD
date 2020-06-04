
from collections import OrderedDict

from scapy.layers.inet import TCP

from InternalLogger.internallogger import InternalLogger
from connection_tracker.iconnectiontracker import IConnectionTracker
from controller.itranslator import IO
from readerwriterlock import rwlock


class NasConnectionTracker(IConnectionTracker):
    """
    Tracker for Network Address Shuffling
    """
    def __init__(self):
        self._connection_buffer = OrderedDict([])
        '''
        Buffer Structure:
        (sourceIP, sourcePort, dest_vIP, dest_rPort): (FIN (Flag received), rIP, enforced (should be used to continue connection))
        enforced: Tell other modules that this connection should be kept alive (even if other security measures prohibit it)
        '''
        self._max_buffer = 1000
        self._mapping = None
        #Write Priority Lock
        self._lock = rwlock.RWLockWrite()

    def set_mapping(self, mapping):
        """
        Change Mapping (HF)
        :param mapping:
        """
        self._mapping = mapping

    def check_buffer(self, packet, io):
        """
        Search in NAS Track Buffer

        :param packet: IPv4 / IPv6 Packet
        :param io: Input/Output
        :return: (rIP or None if no rIP has been found, enforced)
        """
        InternalLogger.get().debug("Searching for connection in buffer")
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if len(self._connection_buffer) > 0:
                #Check for incoming packets
                if io == IO.INPUT:
                    ##WARNING: Use PH function to translate PORTS

                    packet_data = (packet.src, tcp.sport, packet.dst, tcp.dport)
                    InternalLogger.get().debug("Searching in Buffer for: " + str(packet_data))
                    with self._lock.gen_rlock():
                        result = self._connection_buffer.get(packet_data)
                    if result is not None:
                        (fin, ip, enforced) = result
                        InternalLogger.get().debug("Found mapping in buffer")
                        with self._lock.gen_wlock():
                            self._connection_buffer.move_to_end(packet_data, last=False)
                        return (ip, enforced)
                    else:
                        InternalLogger.get().debug("Connection not found")
                else:
                    #Check for leaving packet
                    InternalLogger.get().debug("Searching in Buffer for: " + str(packet.src))
                    result_dst = None
                    result_packet_data = None
                    with self._lock.gen_rlock():
                        #check connections in order
                        #old connections with similar tuple will not be used because of the order
                        for packet_data, (fin, r_ip, enforced) in self._connection_buffer.items():
                            (src, sport, dst, dport) = packet_data
                            if src == packet.dst and dport == tcp.sport and sport == tcp.dport and r_ip == packet.src:
                                InternalLogger.get().debug("Found mapping in buffer (reverse)")
                                result_packet_data = packet_data
                                result_dst = (dst, enforced)
                                break
                    if result_packet_data is not None:
                        with self._lock.gen_wlock():
                            #Check again if it has been deleted (protect against race conditions)
                            if self._connection_buffer.get(packet_data) is not None:
                                self._connection_buffer.move_to_end(result_packet_data, last=False)
                    if result_dst is None:
                        InternalLogger.get().debug("Connection not found (reverse)")
                    return result_dst
        return None

    def track_connection(self, packet, io):
        """

        :param packet: IPv4 / IPv6 Packet
        :param io: Input/Output
        """
        InternalLogger.get().debug("Trying to track connection")
        '''
        called before (incoming) and after (outgoing) ph translations
        tracks connections with virtual ip addresses and real ports
        '''
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            packet_data = None
            if io == IO.INPUT:
                packet_data = (packet.src, tcp.sport, packet.dst, tcp.dport)
            else:
                packet_data = (packet.dst, tcp.dport, packet.src, tcp.sport)
            InternalLogger.get().debug("Tracking packet: " + str(packet_data))
            if tcp.flags.S:
                #SYN has been received, Check if it a new connection
                result = None
                with self._lock.gen_rlock():
                    result = self._connection_buffer.get(packet_data)
                if result is None:
                    InternalLogger.get().debug("SYN received for the first time, trying to add mapping")
                    new_ip = self._mapping.get(packet.dst)
                    if new_ip is not None:
                        with self._lock.gen_wlock():
                            self._connection_buffer[packet_data] = (False, new_ip, False)
                            # (TCP Ident) : (Fin tracked, mapped dst)
                            self._connection_buffer.move_to_end(packet_data, last=False)  # move to the beginning
                            self.clean_buffer()
                    else:
                        InternalLogger.get().debug("No new rIP for connection in tracker")
            elif tcp.flags.F:
                #CFIN has been received, connection will close and receive one more ACK
                result = None
                with self._lock.gen_rlock():
                    result = self._connection_buffer.get(packet_data)
                if result is not None:
                    (fin, ip, enforced) = result
                    InternalLogger.get().debug("FIN received for the first time, FIN = True")
                    with self._lock.gen_wlock():
                        self._connection_buffer[packet_data] = (True, ip, enforced)
            elif tcp.flags.A:
                #Check if last ACK (after FIN) has been received
                result = None
                with self._lock.gen_rlock():
                    result = self._connection_buffer.get(packet_data)
                if result is not None:
                    (fin, ip, enforced) = result
                    if fin:
                        InternalLogger.get().debug("ACK received (Last Ack), deleting mapping")
                        with self._lock.gen_wlock():
                            self._connection_buffer.pop(packet_data)

    def add_connection(self,sourceIP, sourcePort, dest_vIP, dest_rPort, dest_rIP, enforce):
        """
        Add connection information for connection which should be generated in other components

        :param sourcePort: Source Port
        :param sourceIP: Source IP-Address
        :param dest_rPort: Destination virtual Port
        :param dest_vIP:  Destination virtual IP-Address
        :param dest_rIP: Destination real IP-Address
        :param enforce: Tell other modules that this connection should be kept alive (even if other security measures prohibit it)
        """
        with self._lock.gen_wlock():
            packet_data = (sourceIP, sourcePort, dest_vIP, dest_rPort)
            InternalLogger.get().debug("Added external connection to tracker: " + str(packet_data) + ": " + dest_rIP)
            self._connection_buffer[packet_data] = (False, dest_rIP, enforce)
            # (TCP Ident) : (Fin tracked, mapped dst)
            self._connection_buffer.move_to_end(packet_data, last=False)  # move to the beginning


    def get_active_ports(self):
        """
        Get all rPorts that are currently used
        :return: List of Ports
        """
        port_list = []
        with self._lock.gen_rlock():
            for packet_data, (fin, r_ip, enforced) in self._connection_buffer.items():
                (src, sport, dst, dport) = packet_data
                if dport not in port_list:
                    port_list.append(dport)
        return port_list

    def clean_buffer(self):
        """

        """
        # Cleanup
        while len(self._connection_buffer) > self._max_buffer:
            # remove first element(s)
            InternalLogger.get().debug("Removing element from buffer")
            with self._lock.gen_wlock():
                self._connection_buffer.popitem(last=True)

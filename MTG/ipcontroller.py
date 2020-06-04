from concurrent.futures import ThreadPoolExecutor
from threading import Thread
import fnfqueue


from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import _ICMPv6, IPv6
from scapy.layers.l2 import Ether

from InternalLogger.internallogger import InternalLogger
from connection_tracker.iconnectiontracker import IConnectionTracker
from controller.ilayercontroller import ILayerController
from controller.itranslator import IO


class IpController(Thread):
    """

    :param: queue_num: Numer of the IpTables Queue for this controller
    :param: controller: List of controllers or trackers (Hast to implement IConnectionTracker or ILayerController)
    :param: debug_forward: Forward all packets directly, dont use controllers or trackers
    :param: io: Input or Output (Output = Client Net or Host Net to Public Net)
    """
    def __init__(self, queue_num, controller, debug_forward, io):
        Thread.__init__(self)
        self._queue_num = queue_num
        self._debug_direct_forward = debug_forward
        self._executor = ThreadPoolExecutor(max_workers=1000)
        self._controller = controller
        self._io = io

        #test
        self.conn = fnfqueue.Connection()

    def receive(self, pkt):
        """
        Start thread for every new packet

        :param pkt: raw packet from nfQueue
        """
        self._executor.submit(self.handle_packet, pkt)

    def run(self):
        """
            Run this class in new thread and start packet receiver
        """
        InternalLogger.get().debug("Starting IP-Controller, queue_num=" + str(self._queue_num))
        try:
            q = self.conn.bind(self._queue_num)
            q.set_mode(fnfqueue.MAX_PAYLOAD, fnfqueue.COPY_PACKET)
        except PermissionError:
            InternalLogger.get().error("Access denied; Do I have root rights or the needed capabilities?")
            sys.exit(-1)

        while True:
            try:
                for packet in self.conn:
                    self.receive(packet)
            except fnfqueue.BufferOverflowException:
                InternalLogger.get().error("Buffer Error")
                '''
                In case packets arrive too
                fast at the kernel side, the socket buffer overflows and a
                BufferOverflowException is raised.
                '''
                self.conn.reset() # try to solve Overflow
                pass
            except Exception as e:
                InternalLogger.get().critical("Error: " + str(e), exc_info=True)

    def handle_packet(self, pkt):
        """
        Forward packets to layer controllers and trackers

        :param pkt: Raw Packet
        """
        try:
            InternalLogger.get().debug("---Detected packet (" + str(pkt) + "),\t queue_num=" + str(self._queue_num))
            data = pkt.payload
            # Detect v4/v6 and load as IP object
            ip_packet = None
            try:
                ip_packet = IPv6(data)
                ip_version = 6
            except Exception as e:
                InternalLogger.get().debug("Exception in IPv6 Packet, trying IPv4")
            if ip_packet is None or ip_packet.version == 4:
                ip_packet = IP(data)
                ip_version = 4
            # Output data
            InternalLogger.get().debug("--Source: " + ip_packet.src + "\tDest: " + ip_packet.dst + "\tIPv" + str(ip_version))

            if self._debug_direct_forward:
                #Directly forward
                InternalLogger.get().debug("DEBUG: Forwarding")
                pkt.mangle()
            else:
                InternalLogger.get().debug("Checking layers")
                forward = self.check_layers(ip_packet)
                #check if the packet should be forwarded to the network stack (Attention: internal ip routes are responsible to forward it)
                if forward:
                    InternalLogger.get().debug("Recalculating checksums and length")
                    self.recalculate_checksums(ip_packet, ip_version)
                    InternalLogger.get().debug("Sending packet")
                    #Redirect packet to network stack
                    pkt.payload = raw(ip_packet)
                    pkt.mangle()
                else:
                    InternalLogger.get().debug("Dropped")
                    #Dont forward to localhost or another host, drop
                    pkt.drop()

        except Exception as e:
            InternalLogger.get().critical("Error: " + str(e), exc_info=True)


    def check_layers(self, packet):
        """
        Hand over packets to the layer controller or trackers

        :param packet: ipv4 / ipv6 packet (scapy), packet can be modified in this method
        :return: forward (should it be forwarded to the network stack)
        """
        forward = True
        #check every controller or translator
        for (id, controller) in sorted(self._controller.items()):
            if isinstance(controller, ILayerController):
                # check if layer for controller exists
                layer_types = controller.layers()
                for layer in layer_types:
                    if packet.haslayer(layer):
                        InternalLogger.get().debug("Forwarding to controller" + str(type(controller)))
                        #original packet, translators can modify
                        forward_controller = controller.process_packet(packet)
                        forward = forward and forward_controller
                        break # Dont send to controller twice
            elif isinstance(controller, IConnectionTracker):
                #Copy Packet, dont allow to change it
                #Track in new thead (no realtime changes required)
                packet_copy = copy.deepcopy(packet)
                InternalLogger.get().debug("Forwarding to tracker" + str(type(controller)))
                self._executor.submit(self.forward_to_tracker, controller, packet_copy, self._io)
        return forward

    def forward_to_tracker(self, tracker, packet, io):
        """
        Execute tracker method

        :param tracker: Tracker (IConnectionTracker)
        :param packet: IPv4/IPv6 Packet
        :param io: Input or Output
        """
        tracker.track_connection(packet, io)

    def recalculate_checksums(self, ip_packet, ip_version):
        """
        Recalculate all necessary checksums

        :param ip_packet: IPv4 /IPv6 Packet
        :param ip_version: IP version
        """
        layers = self.get_packet_layers(ip_packet)
        if ip_version == 4:
            # recalculate IPv4 checksum
            del ip_packet.chksum
            del ip_packet.len
        for layer in layers:
            #recalculate layer checksums
            if isinstance(layer, _ICMPv6):
                del layer.cksum
            if isinstance(layer, UDP):
                del layer.chksum
                del layer.len
            if isinstance(layer, TCP):
                del layer.chksum

    def get_packet_layers(self, packet):
        """
        Get all layers of the packet
        :param packet: IPv4 / IPv6 Packet
        :returns List of Protocols
        """
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break

            yield layer
            counter += 1

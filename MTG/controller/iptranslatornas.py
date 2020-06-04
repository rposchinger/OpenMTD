from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6

from InternalLogger.internallogger import InternalLogger
from controller.helper.networkhelper import NetworkHelper
from controller.ilayercontroller import ILayerController
from controller.itranslator import IO
from netaddr import *

class IPTranslatorNAS(ILayerController):
    """
    Network Address Shuffling Controller
    """
    def layers(self):
        """

        :return:list of layers translated by this controller
        """
        return [IP, IPv6]

    def __init__(self, mapping, whitelist, io, track, nas_tracker, dynamic_port_priority):
        """

        :param mapping: HF Mapping
        :param whitelist: Whitelist IPs
        :param io: Input or Output
        :param track: Track Connections (Bool)
        :param nas_tracker: NAS Tracker Class (IConnectionTracker)
        """
        self._nas_tracker = nas_tracker
        super().__init__(mapping, io)
        self._whitelist = whitelist
        self._track = track
        self._network_helper = NetworkHelper()
        self._dyn_port_priority = dynamic_port_priority
        self._honeypot = False
        self._honey_v4 = None
        self._honey_v6 = None

    def set_honeypot(self, v4, v6):
        self._honeypot = True
        self._honey_v4 = v4
        self._honey_v6 = v6

    def process_packet(self, packet):
        """

        :param packet: IPv4 /Ipv6 Packet
        :return: Forward?
        """
        #manipulate incoming packet
        if self._io == IO.INPUT:
            if self._mapping is not None:
                new_ip = self._mapping.get(packet.dst)
                #vIP found in Mapping
                if new_ip is not None:
                    packet.dst = new_ip
                    InternalLogger.get().debug("DST changed to " + new_ip + "(from mapping)")
                else:
                #no vIP found in mapping
                    is_whitelist = False
                    #search in whitelist
                    for whitelist_address in self._whitelist:
                        if packet.dst in IPNetwork(whitelist_address):
                            is_whitelist = True
                            break
                    if is_whitelist:
                        InternalLogger.get().debug("IP-NAS: Forwarding the incoming packet, "
                                                   "whitelist")
                        return True
                    #search in local addresses (should it be forwarded to this host internally?)
                    elif packet.dst in self._network_helper.local_addresses():
                        InternalLogger.get().debug("IP-NAS: Accepting the incoming packet, destination = local address")
                        return True

                    #search for vIP in Connection Tracker
                    InternalLogger.get().debug("No mapping, searching tracker buffer")
                    new_ip_tracked = None
                    if self._track:
                        new_ip_tracked = self.check_buffer(packet)
                    else:
                        InternalLogger.get().debug("WARNING: Tried to reach MT Area, DROPPED")
                    if new_ip_tracked is not None:
                        #vIP found
                        packet.dst = new_ip_tracked
                    else:
                        #Send to honeypot?
                        if self._honeypot and packet.haslayer(TCP):
                            vsubnet = False
                            #check if destination is part of the virtual subnet
                            if self._virtual_subnets is not None:
                                for subnet in self._virtual_subnets:
                                    if packet.dst in IPNetwork(subnet):
                                        vsubnet = True
                                        break
                            else:
                                InternalLogger.get().error("No virtual subnets")
                            if vsubnet:
                                #dst is in vSubnet, set honeypot
                                new_ip_honeypot = None
                                if IPAddress(packet.dst).version == 4:
                                    new_ip_honeypot = self._honey_v4
                                else:
                                    new_ip_honeypot = self._honey_v6
                                if new_ip_honeypot is not None:
                                    #add to connection tracking:
                                    tcp = packet[TCP]
                                    self._nas_tracker.add_connection(packet.src, tcp.sport, packet.dst, tcp.dport, new_ip_honeypot, True)
                                    packet.dst = new_ip_honeypot

                                    InternalLogger.get().debug("WARNING: Tried to reach MT Area, forwarded to HONEYPOT (" + new_ip_honeypot + ")")
                                    return True
                                else:
                                    InternalLogger.get().error("No HoneyPot Address")
                                    return False
                            else:
                                InternalLogger.get().debug("WARNING: Tried to reach MT Area, DROPPED (Not in Virtual Subnet, Honeypot not used)")
                        else:
                            #vIP not found
                            InternalLogger.get().debug("WARNING: Tried to reach MT Area, DROPPED")
                            return False
            else:
                InternalLogger.get().critical("ERROR: No mapping")

        # manipulate leaving packet
        else:
            #look for existing mapping in TRACKER first (to ignore mapping for internal rIP if the connection is still being tracked)
            new_ip_tracked = None
            if self._track:
                new_ip_tracked = self.check_buffer(packet)
            if new_ip_tracked is not None:
                packet.src = new_ip_tracked
                InternalLogger.get().debug("SRC changed to  " + new_ip_tracked + " (from buffer)")
            #not in tracking, search in mapping
            else:
                new_ip = self._mapping.get(packet.src)
                if new_ip is not None:
                    packet.src = new_ip
                    InternalLogger.get().debug("SRC changed to " + new_ip + "(from mapping)")
                else:
                    InternalLogger.get().debug("Forwarding the leaving packet, SRC != MTD Host")
        return True

    def check_buffer(self, packet):
        """
        Check if a mapping for the connection exisits in the connection tacker buffer
        :param packet:
        :return:
        """
        tracked_ip = None
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            port = 0
            if self._io == IO.INPUT:
                port = tcp.dport
            else:
                port = tcp.sport
            # check if this connection is allowed to continue based on connection tracking
            result = self._nas_tracker.check_buffer(packet, self._io)

            if result is not None:
                (ip, enforced) = result
                if self._dyn_port_priority.allow_continue(port) or enforced:
                    tracked_ip = ip
                else:
                    InternalLogger.get().debug(
                        "DynPort Priority doesnt allow the connection to continue (dest rPort = " + str(port) + ") and it has not been enforced")
        return tracked_ip



    def mapping_changed(self):
        """
        Forward new Mapping to the tracker
        """
        if self._nas_tracker is not None:
            self._nas_tracker.set_mapping(self._mapping)
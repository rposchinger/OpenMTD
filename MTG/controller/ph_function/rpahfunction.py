import hashlib
from collections import OrderedDict
from random import random, randint

from InternalLogger.internallogger import InternalLogger
from controller.ph_function.iphfunction import IPhFunction
from datetime import datetime


class RpahFunction(IPhFunction):
    """
        RPAH inspired Port Hopping Function
    """
    def __init__(self, hopping_period, max_buffer):
        """

        :param hopping_period: Hopping Period in Seconds
        :param max_buffer: Maximum Hash Buffer
        """
        super().__init__()
        self._hopping_period = hopping_period
        self._hash_buffer = OrderedDict()
        self._max_buffer = max_buffer

    def real_port_to_vport(self, r_port, client_ip, client_key):
        """

        :param r_port: Int, Real Port
        :param client_ip: String, Client IP Address
        :param client_key: String, Client PreShared Key
        :return: Virtual Port, Int
        """
        t = self.get_T()
        h = self.get_hash(t, client_key, client_ip)
        v_port = h ^ r_port
        InternalLogger.get().debug("RPAH vPort =" + str(v_port))
        return v_port

    def virtual_port_to_rport(self, v_port, client_ip, client_key):
        """

        :param v_port: Int, Virtual Port
        :param client_ip: String, Client IP Address
        :param client_key: String, Client PreShared Key
        :return: Real Port, Int
        """
        t = self.get_T()
        h = self.get_hash(t, client_key, client_ip)
        r_port = h ^ v_port
        InternalLogger.get().debug("RPAH rPort =" + str(r_port))
        return r_port

    def get_T(self):
        """
        get T, time interval value
        :return: T
        """
        now = datetime.now()
        timestamp = datetime.timestamp(now)
        #random time
        #timestamp = timestamp + (randint(-3, 3) / 10)

        return int(timestamp / self._hopping_period)

    def get_hash(self, t, key, client_ip):
        """

        :param t:  t = T = Time Interval Value
        :param key: PSK
        :param client_ip: IP of the Client
        :return: Hash
        """

        #Search in Buffer first
        InternalLogger.get().debug("Searching for hash in buffer")
        hash_int = self._hash_buffer.get((t, key, client_ip))
        if hash_int is not None:
            InternalLogger.get().debug("Found hash in buffer")
            self._hash_buffer.move_to_end((t, key, client_ip), last=False)
            return hash_int

        # Generate
        InternalLogger.get().debug("Trying to generate hash")
        h = hashlib.blake2b(digest_size=2)          # optimized for 64 bit
        h.update(bytes(t))
        h.update(key.encode())
        h.update(client_ip.encode())
        hash_result = h.digest()
        hash_int = int.from_bytes(hash_result, byteorder='big',  signed=False)

        # Save to buffer
        self._hash_buffer[(t, key, client_ip)] = hash_int
        self._hash_buffer.move_to_end((t, key, client_ip), last=False) # move to the beginning
        # Cleanup
        while(len(self._hash_buffer) > self._max_buffer):
            #remove first element(s)
            self._hash_buffer.popitem(last=True)
        return hash_int

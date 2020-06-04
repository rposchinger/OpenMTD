import netifaces

class NetworkHelper:
    """
    All network functions (just one at the moment, but we'll see)
    """
    def __init__(self):
        self._if_ext = None
        self._mode = [netifaces.AF_INET, netifaces.AF_INET6]

    def local_addresses(self):
        """
        :return: All Local addresses
        """
        if self._if_ext is None:
            interfaces = netifaces.interfaces()
            if_ext = []
            for i in interfaces:
                for mode in self._mode:
                    iface = netifaces.ifaddresses(i).get(mode)
                    if iface:
                        for j in iface:
                            if_ext.append(j['addr'])
            self._if_ext = if_ext
        return self._if_ext

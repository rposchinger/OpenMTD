import abc

class IPhFunction():
    @abc.abstractmethod
    def virtual_port_to_rport(self, v_port, client_ip, client_key):
        """
        Return vPort for rPort
        Return None if no valid port could be found
        :param client_key: String
        :param client_ip: String
        :rtype: int (Port)
        :param v_port: virtual port
        """
        pass

    @abc.abstractmethod
    def real_port_to_vport(self, r_port, client_ip, client_key):
        """
        Return rPort for vPort
        Return None if no valid port could be found
        :param client_key: String
        :param client_ip:  String
        :rtype: int (Port)
        :param r_port: virtual port
        """
        pass


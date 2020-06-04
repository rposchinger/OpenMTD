from controller.ph_function.iphfunction import IPhFunction


class TestPhFunction(IPhFunction):
    """

    """
    def __init__(self, mapping, io):
        super().__init__(mapping, io)

    def real_port_to_vport(self, r_port, client_ip, client_key):
        """

        :param r_port:
        :param client_ip:
        :param client_key:
        :return:
        """
        return r_port + 8000

    def virtual_port_to_rport(self, v_port, client_ip, client_key):
        """

        :param v_port:
        :param client_ip:
        :param client_key:
        :return:
        """
        return v_port - 8000


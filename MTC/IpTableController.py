import paramiko
from netaddr import *


class IpTableController:
    """

    """
    def __init__(self, ip, username, password, gateway_mapping, honeypot_gateway, virtual_subnets):
        self._ip = ip
        self._username = username
        self._password = password
        self._mapping = None
        self._gateway_mapping = gateway_mapping
        self._honeypot_gateway = honeypot_gateway
        self._virtual_subnets = virtual_subnets

    def send_mapping(self, mapping):
        """

        :param mapping:
        """
        old_mapping = self._mapping
        self._mapping = mapping
        ssh = paramiko.SSHClient()
        # dangerous, should be removed later
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self._ip, username=self._username, password=self._password)

        self.clean_up(ssh, old_mapping)

        self.generate_rules(ssh, self._mapping)
        ssh.close()

    def generate_rules(self, ssh, new_mapping):
        """

        :param ssh:
        :param new_mapping:
        """
        for subnet, gateway in self.generate_honeypot_mapping().items():
            self.add_route(subnet, gateway, ssh)

        for subnet, ip in new_mapping.items():
            selected_gateway = None
            for gateway_subnet, gateway in self._gateway_mapping.items():
                if IPAddress(ip) in IPNetwork(gateway_subnet):
                    selected_gateway = gateway
                    break
            if selected_gateway is not None:
                self.add_route(subnet, gateway, ssh)
            else:
                print("Error: Not gateway found for " + ip + ";" + subnet)

    def add_route(self, subnet, gateway, ssh):
        if IPNetwork(subnet).version == 4:
            command = "sudo ip "
        else:
            command = "sudo ip -6 "
        command += "route add " + subnet + " via " + gateway
        print("Executing: " + command)
        stdin, stdout, stderr = ssh.exec_command(command)
        print(stdout.read())
        print(stderr.read())

    def generate_honeypot_mapping(self):
        honeypot_mapping = {}
        for subnet in self._virtual_subnets:
            v = IPNetwork(subnet).version
            for honeypot_gateway_address in self._honeypot_gateway:
                if v == IPAddress(honeypot_gateway_address).version:
                    honeypot_mapping[subnet] = honeypot_gateway_address
                    break
        return honeypot_mapping


    def clean_up(self, ssh, old_mapping):
        """

        :param ssh:
        :param old_mapping:
        """
        if old_mapping is not None:
            for subnet, ip in old_mapping.items():
                if subnet in self._mapping:
                    if self._mapping.get(subnet) == ip:
                        #dont delete mapping that is in new mapping
                        continue

                if IPAddress(ip).version == 4:
                    command = "sudo ip "
                else:
                    command = "sudo ip -6 "
                command += "route del "
                command += subnet
                print("Executing: " + command)
                stdin, stdout, stderr = ssh.exec_command(command)
                print(stdout.read())
                print(stderr.read())


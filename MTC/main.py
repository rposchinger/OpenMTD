import time
import traceback
from threading import Thread
import requests
import json
import secrets

from netaddr import IPNetwork
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException
from requests.exceptions import ConnectionError

from IpTableController import IpTableController


class MTC(Thread):
    def run(self):
        """

        """
        conf_data = None
        with open('conf.json') as json_file:
            conf_data = json.load(json_file)

        self.hostsv4 = conf_data["hostsv4"]
        self.hostsv6 = conf_data["hostsv6"]
        self.honeypot_gateway = conf_data["honeypot_gateway"]
        self.virtual_subnets = conf_data["virtual_subnets"]
        # host subnet to gateway (MTG)
        self.gateway_mapping = conf_data["gateway_mapping"]
        self.subnetv4 = conf_data["subnetv4"]
        self.subnetv6 = conf_data["subnetv6"]
        self.urls = conf_data["urls"]
        # controller rest adress : controller subnet

        self.hopping_period = conf_data["hopping_period"]
        self.mapping_buffer = {}
        self.mapping_count = 0
        self.max_mapping_sliding_window = conf_data["max_mapping_sliding_window"]

        iptable_data  = conf_data["router"]
        iptable_controller = IpTableController(iptable_data["ip"], iptable_data["username"], iptable_data["password"], self.gateway_mapping, self.honeypot_gateway, self.virtual_subnets)
        try:
            print("Starting MTC")
            lfmapping = None
            while True:
                try:
                    print("Recalculating mapping")
                    #autoamtically generate subnet of subnets
                    #list(ip_network('192.0.2.0/24').subnets(new_prefix=25))
                    self.save_mapping_to_buffer(lfmapping)
                    old_and_new_mapping = {}
                    for (count, mapping) in self.mapping_buffer.items():
                        print(count)
                        print(mapping)
                        old_and_new_mapping.update(mapping)
                    lfmapping = self.recalculate_mapping(self.hostsv4, self.subnetv4, old_and_new_mapping)
                    lfmapping.update(self.recalculate_mapping(self.hostsv6, self.subnetv6, old_and_new_mapping))
                    old_and_new_mapping.update(lfmapping)
                    print("Buffer Orig:")
                    print(self.mapping_buffer)
                    print("Buffer and new mapping:")
                    print(old_and_new_mapping)
                    print("New mapping")
                    print(lfmapping)
                    iptable_controller.send_mapping(old_and_new_mapping)
                    #just send required mappings for gateway
                    for url, url_assigned_subnets in self.urls.items():
                        print("Generating mapping for " + url)
                        mapping_for_gateway = {}
                        for subnet_map, address in old_and_new_mapping.items():
                            for url_assigned_subnet in url_assigned_subnets:
                                if address in IPNetwork(url_assigned_subnet):
                                    #reverse standard
                                    mapping_for_gateway[address] = subnet_map
                        json_structure = {}
                        json_structure["lf"] = mapping_for_gateway
                        json_structure["virtual_subnets"] = self.virtual_subnets
                        json_mapping = json.dumps(json_structure)
                        headers = {"Content-Type": "application/json"}
                        print("Sending Mapping to: " + url)
                        print(mapping_for_gateway)
                        r = requests.put(url, data=json_mapping, headers=headers)
                        print("Status: " + str(r.status_code))
                    time.sleep(self.hopping_period)
                except ConnectionError as eC:
                    print(eC)
                except (AuthenticationException, BadHostKeyException) as e:
                    print("Could not authenticate")
                except (SSHException, EOFError) as e:
                    print("Can not connect: " + str(e))


        except KeyboardInterrupt as e:
            print(e)
        except Exception as e:
            print("Error: " + str(e))
            print(traceback.format_exc())

    def revert(self, dict):
        """

        :param dict:
        :return:
        """
        return {v: k for k, v in dict.items()}

    def recalculate_mapping(self, hosts, subnets, old_mapping):
        """

        :param hosts:
        :param subnets:
        :param old_mapping:
        :return:
        """
        all_subnets = subnets.copy()
        mapping = {}
        for host in hosts:
            while True: # wtf, no do-while in python
                rand = secrets.randbelow(len(all_subnets))
                subnet = all_subnets.pop(rand)
                if subnet not in mapping.keys() and subnet not in old_mapping.keys():
                    mapping[subnet] = host
                    break
        return mapping

    def save_mapping_to_buffer(self, mapping):
        """

        :param mapping:
        :return:
        """
        if mapping is None:
            return
        self.mapping_buffer[self.mapping_count] = mapping
        self.mapping_count += 1
        self.clean_up_mapping_buffer()

    def clean_up_mapping_buffer(self):
        """

        """
        delete_id = []
        for (count, mapping) in self.mapping_buffer.items():
            if self.mapping_count - count > self.max_mapping_sliding_window:
                delete_id.append(count)
        for id in delete_id:
            del self.mapping_buffer[id]

if __name__ == "__main__":
    mtc = MTC()
    mtc.start()

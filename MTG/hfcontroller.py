import json
import secrets
import time
from concurrent.futures.thread import ThreadPoolExecutor
from threading import Thread
import requests
from netaddr import IPNetwork

from InternalLogger.internallogger import InternalLogger


class HfController(Thread):
    """
    High Frequency Controller
    Calculates new rIP based on the Subnets received by the LFMappingAPI
    """
    def __init__(self, translators, receiver, hopping_period, dynamic_port_priority):
        Thread.__init__(self)
        self._translators = translators
        self._lf_mapping = None
        self._hf_mapping_old = None
        self._hf_mapping = None
        self._hopping_period = hopping_period
        self._hf_mapping_other = {}
        self._receiver = receiver
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._dynamic_port_priority = dynamic_port_priority

    def run(self):
        """
        Run HFController in new thread
        Recalculate mappings (rIP addresses) regulary in a time interval (hopping period)
        """
        try:
            while True:
                InternalLogger.get().debug("HF Controller starting")
                InternalLogger.get().debug("--------------------------------------------------------------")
                if self._dynamic_port_priority.block_hf_shuffling():
                    InternalLogger.get().debug("HF Recalculate Process blocked by DynPortPriority")
                else:
                    self.recalculate_mapping()

                InternalLogger.get().debug("HF Controller stopping")
                InternalLogger.get().debug("--------------------------------------------------------------")
                time.sleep(self._hopping_period)
        except KeyboardInterrupt as e:
            InternalLogger.get().debug(e)
        except Exception as e:
            InternalLogger.get().error("Error: " + str(e), exc_info=True)

    def recalculate_mapping(self):
        """
        Recualculate mapping (rIP addresses)
        """
        InternalLogger.get().info("--HF Controller recalculating mapping")
        new_mapping = {}
        if self._lf_mapping is not None:
            # Calculate new vIP for every rIP (ip) and the given subnet
            for ip, subnet in self._lf_mapping.items():
                InternalLogger.get().debug("-Checking " + ip + ", subnet " + subnet)
                #create network of the subnet
                network = IPNetwork(subnet)
                #get network size
                total_count = network.size
                #select random vIP
                rand = secrets.randbelow(total_count)
                InternalLogger.get().debug(str(total_count) + " addresses possible")
                v_ip = str(network[rand])
                InternalLogger.get().debug("New IP: " + str(v_ip))
                #Set mapping
                new_mapping[v_ip] = ip
        else:
            InternalLogger.get().debug("Error: No LF Mapping")
        InternalLogger.get().debug("--HF Controller finished")
        InternalLogger.get().debug(new_mapping)
        #save old mapping and set new mapping
        self._hf_mapping_old = self._hf_mapping
        self._hf_mapping = new_mapping
        #send new mapping to other gatways (defined in nas/receiver) if necessary
        self.send_new_mapping()

    def send_new_mapping(self):
        """
        Merge external (other gateways) and internal mappings
        send new mapping to the receivers = translators (trackers/controllers) internally
        send new mapping to other gatways (defined in nas/receiver) if necessary
        """
        total_mapping = {}
        #Internal mapping
        if self._hf_mapping is not None:
            total_mapping.update(self._hf_mapping)
        #external mapping
        if self._hf_mapping_other is not None:
            total_mapping.update(self._hf_mapping_other)
        #send new mapping to translators
        for translator in self._translators:
            #POSSIBLE: total_mapping just for DNS
            translator.set_mapping(total_mapping)
        InternalLogger.get().debug("Total Mapping")
        InternalLogger.get().debug(total_mapping)
        #send new mapping to other gateways
        self._executor.submit(self.send_all_rest)

    def set_lf_mapping(self, mapping):
        """
        called by REST endpoint

        Set LF (Low Frequency) Mapping for this gateway (possible interfaces for every MT host)
        :param mapping: Mapping
        """
        self._lf_mapping = mapping
        #Recalculate total mapping (merge) and send
        self.recalculate_mapping()

    def add_hf_mapping(self, hf_mapping):
        """
        called by REST endpoint

        add high frequency mapping from other gateway to internal mapping

        :param hf_mapping: high frequency mapping
        """
        InternalLogger.get().debug("Adding addresses")
        InternalLogger.get().debug(hf_mapping)
        self._hf_mapping_other.update(hf_mapping)
        # Recalculate total mapping (merge) and send
        self.send_new_mapping()

    def revoke_hf_mapping(self, hf_mapping):
        """
        called by REST endpoint

        revoke parts of the high frequency mapping from other gateways

        :param hf_mapping: revoked high frequency mapping
        """



        InternalLogger.get().debug("Revoking addresses")
        InternalLogger.get().debug(hf_mapping)
        #delete revoked mappings
        for v_ip, r_ip in hf_mapping.items():
            if self._hf_mapping_other.get(v_ip) is not None:
                del self._hf_mapping_other[v_ip]
        # Recalculate total mapping (merge) and send
        self.send_new_mapping()

    def send_all_rest(self):
        """
        Send the High Frequency mapping (total) to Receivers (REST endpoint of other gateways) if necessary
        """
        try:
            for url in self._receiver:
                #Send mapping to url of receiver
                InternalLogger.get().debug("Sending Mapping to: " + url)
                #Create structure
                json_structure = {}
                #add new mapping
                json_structure["hf_added"] = self._hf_mapping
                #revoke old mapping
                json_structure["hf_revoked"] = self._hf_mapping_old
                json_mapping = json.dumps(json_structure)
                headers = {"Content-Type": "application/json"}
                #Send via HTTP
                r = requests.put(url, data=json_mapping, headers=headers)
                InternalLogger.get().debug("Status: " + str(r.status_code))
        except Exception as e:
            InternalLogger.get().error("Error: " + str(e), exc_info=True)

    def set_hf_subnet(self, subnets):
        for translator in self._translators:
            #POSSIBLE: total_mapping just for DNS
            translator.set_virtual_subnets(subnets)


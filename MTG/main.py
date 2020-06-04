import json
import sys
from threading import Thread

from flask import Flask
from flask_restful import Api

from scapy.layers.dns import DNSRR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6

from InternalLogger.internallogger import InternalLogger
from connection_tracker.dynamic_port_priority import DynamicPortPriority
from controller.dnstranslator import DnsTranslator
from controller.iptranslatornas import IPTranslatorNAS
from controller.itranslator import IO
from connection_tracker.nasconnectiontracker import NasConnectionTracker
from controller.ph_function.rpahfunction import RpahFunction
from controller.portcontrollerph import PortTranslatorPh
from hfcontroller import HfController
from ipcontroller import IpController
from rest.lfmappingapi import LfMappingApi

app = Flask(__name__)
'''
Incoming:

10: PortControllerPH
30: NasConnectionTracker
50: IpTranslatorNAS

Leaving:

50: IpTranslatorNAS
51: DnsTranslator
70: NasConnectionTracker
100: PortController PH

'''

def main():
    """
    COMPOSITION ROOT of the MTG / MTPG

    Load Configuration, start and configure PH/NAS components
    """

    conf_data = None
    with open('conf.json') as json_file:
        conf_data = json.load(json_file)

    whitelist = conf_data["whitelist"]
    enable_file_logging = conf_data["file_logging"]
    enable_debug_output = conf_data["debug_output"]
    InternalLogger.init(enable_file_logging, enable_debug_output)
    InternalLogger.get().info("Starting...")

    debug_forward = conf_data["debug_forward"]
    conf_data_nas = conf_data["nas"]
    conf_data_ph = conf_data["ph"]
    enable_nas = conf_data_nas["activate"]
    enable_ph = conf_data_ph["activate"]

    layer_controller_out = {}
    layer_controller_in = {}
    ip_translators = None
    dynamic_port_priority = None
    # Enable Network Address Shuffling
    if enable_nas:
        conf_data_nas = conf_data["nas"]
        InternalLogger.get().info("Starting NAS")
        dns_ttl = conf_data_nas["dns_ttl"]
        # Set Controllers
        dns = DnsTranslator(None, dns_ttl)

        conf_data_nas_tracking_honeypot = conf_data_nas["honeypot"]
        honeypot = conf_data_nas_tracking_honeypot["activate"]

        tracker = None
        conf_data_nas_tracking = conf_data_nas["tracking"]
        enable_nas_track = conf_data_nas_tracking["activate"]
        if enable_nas_track:
            #Enable Tracking
            tracker = NasConnectionTracker()
            layer_controller_out[70] = tracker
            layer_controller_in[30] = tracker

            #Enable Dynamic Port Priority
            conf_data_nas_tracking_priority = conf_data_nas_tracking["dynamic_port_priority"]
            continue_list = conf_data_nas_tracking_priority["continue"]
            priority_list = conf_data_nas_tracking_priority["priority"]
            priority_def_list = conf_data_nas_tracking_priority["priority_def"]
            continue_all = conf_data_nas_tracking["continue_all"]
            dynamic_port_priority = DynamicPortPriority(continue_list, priority_list, priority_def_list, continue_all, tracker)

        ip_out = IPTranslatorNAS(None, whitelist, IO.OUTPUT, enable_nas_track, tracker, dynamic_port_priority)
        ip_in = IPTranslatorNAS(None, whitelist, IO.INPUT, enable_nas_track, tracker, dynamic_port_priority)

        honeypot_v4_address = None
        honeypot_v6_address = None
        if honeypot:
            honeypot_v4_address = conf_data_nas_tracking_honeypot["v4_address"]
            honeypot_v6_address = conf_data_nas_tracking_honeypot["v6_address"]
            if honeypot_v6_address is None or honeypot_v4_address is None:
                InternalLogger.error("Honeypot address not set")
                return
            ip_in.set_honeypot(honeypot_v4_address, honeypot_v6_address)
            ip_out.set_honeypot(honeypot_v4_address, honeypot_v6_address)

        layer_controller_out[51] = dns
        layer_controller_out[50] = ip_out

        layer_controller_in[50] = ip_in


        ip_translators = [dns, ip_out, ip_in]

    # Enable PortHopping
    if enable_ph:
        InternalLogger.get().info("Starting PH")
        # Set Controllers
        enable_ph_client = conf_data_ph["client"]
        max_buffer = conf_data_ph["max_buffer"]
        hopping_period = conf_data_ph["hopping_period"]

        ph_function = RpahFunction(hopping_period, max_buffer)
        keymap = conf_data_ph["keymap"]
        subnets_server = conf_data_ph["ph_subnets_server"]
        #tracker needs to use ph function to preserve tracking
        # ph_function = TestPhFunction()
        ph_out = PortTranslatorPh(ph_function, IO.OUTPUT, whitelist, enable_ph_client, keymap, subnets_server)
        layer_controller_out[100] = ph_out

        ph_in = PortTranslatorPh(ph_function, IO.INPUT, whitelist, enable_ph_client, keymap, subnets_server)
        layer_controller_in[10] = ph_in

    if not (enable_nas or enable_ph):
        InternalLogger.get().warning("WARNING: PH and NAS not activated")

    incoming_data = IpController(1, layer_controller_in, debug_forward, IO.INPUT)
    incoming_data.start()
    leaving_data = IpController(2, layer_controller_out, debug_forward, IO.OUTPUT)
    leaving_data.start()

    if enable_nas:
        # Start HF Controller
        if ip_translators is None:
            InternalLogger.get().debug("WARNING: No Translators")
        hf_receiver = conf_data_nas["receiver"]
        hopping_period = conf_data_nas["hopping_period"]
        controller = HfController(ip_translators, hf_receiver, hopping_period, dynamic_port_priority)
        controller.set_lf_mapping(None)
        controller.start()
        subnetmapping_receiver = [controller]

        rest_local = conf_data_nas["rest_iface"]
        InternalLogger.get().info("Starting rest at: " + rest_local)

        # Start Rest API
        api = Api(app)
        api.add_resource(LfMappingApi, '/v1.0/nas_mapping', endpoint='nas_mapping',
                         resource_class_kwargs={'subnet_controller': subnetmapping_receiver})
        Thread.start(run_flask(rest_local))


def run_flask(rest_local):
    """

    :param rest_local: Local rest ip
    """
    app.run(debug=False, use_reloader=False, host=rest_local)


if __name__ == "__main__":
    main()

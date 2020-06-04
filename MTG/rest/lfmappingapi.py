import traceback

from flask_restful import Resource
from flask import request

from InternalLogger.internallogger import InternalLogger


class LfMappingApi(Resource):
    """
        REST API
        Receives LF mappings from the controller
        and HF mapping from other gateways
    """
    def __init__(self, subnet_controller):
        self._subnet_controller = subnet_controller

    def put(self):
        """
        HTTP Put Request
        """
        try:
            InternalLogger.get().debug("Received mapping")
            #Check for json errors
            data = request.json
            if data is None:
                InternalLogger.get().debug("Error: No JSON Data")
                return
            if type(data) is not dict:
                InternalLogger.get().debug("Error: No Dictionary")
                return
            #Receive LF Data
            lf = data.get("lf")
            if lf is not None:
                InternalLogger.get().debug("-> lf mapping received")
                for controller in self._subnet_controller:
                    controller.set_lf_mapping(lf)
            #Received new HF Data
            hf_added = data.get("hf_added")
            if hf_added is not None:
                InternalLogger.get().debug("-> hf_added mapping received")
                for controller in self._subnet_controller:
                    controller.add_hf_mapping(hf_added)
            #Receive revoked HF Data
            hf_revoked = data.get("hf_revoked")
            if hf_revoked is not None:
                InternalLogger.get().debug("-> hf_revoked mapping received")
                for controller in self._subnet_controller:
                    controller.revoke_hf_mapping(hf_revoked)
            lf_subnet = data.get("virtual_subnets")
            if lf_subnet is not None:
                for controller in self._subnet_controller:
                    controller.set_hf_subnet(lf_subnet)


        except Exception as e:
            InternalLogger.get().debug("Error: " + str(e))
            InternalLogger.get().debug(traceback.format_exc())


    def get(self):
        """
        Not Implemented
        :return:
        """
        return "Not implemented"

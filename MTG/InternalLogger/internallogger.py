import logging
import sys
from logging.handlers import RotatingFileHandler


class InternalLogger:
    logger = None

    @staticmethod
    def get():
        """

        :return:
        """
        if InternalLogger.logger is None:
            print("WARNING: No logger")
        return InternalLogger.logger

    @staticmethod
    def init(enable_file_logging, enable_debug_output):
        """
        Init Inetnalllogger
        :param enable_file_logging:
        :param enable_debug_output:
        """
        #Set Format and Name
        InternalLogger.logger = logging.getLogger("MTD")
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        #Set Debug Level for InternalLogger
        if enable_debug_output or enable_file_logging:
            InternalLogger.logger.setLevel(logging.DEBUG)
        else:
            InternalLogger.logger.setLevel(logging.INFO)
        #Create StreamHandler (Console Output)
        stream_handler = logging.StreamHandler()
        if enable_debug_output:
            stream_handler.setLevel(logging.DEBUG)
        else:
            stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(formatter)
        InternalLogger.logger.addHandler(stream_handler)
        #Create FileHandler
        if enable_file_logging:
            file_handler = RotatingFileHandler('mtg.log', maxBytes=10000, backupCount=5)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            InternalLogger.logger.addHandler(file_handler)

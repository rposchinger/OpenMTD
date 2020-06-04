from InternalLogger.internallogger import InternalLogger


class DynamicPortPriority:
    """
    Dynamic Port Priority
    """
    def __init__(self, continue_list, priority_list, priority_definition,  continue_all, nas_connection_tracker):
        self._continue_list = continue_list
        self._priority_list = priority_list
        self._priority_definition = priority_definition
        self._nas_connection_tracker = nas_connection_tracker
        self._continue_all = continue_all

        self._shuffling_blocked_count = 0

    def allow_continue(self, port):
        """
        Check if Connection is allowed to continue based on connection tracking

        :param port: rPort of the destination
        :returns Boolean
        """
        if self._continue_all:
            return True
        return port in self._continue_list

    def block_hf_shuffling(self):
        """
        Check if HF Shuffling should be blocked

        :returns Boolean
        """
        if self._continue_all:
            #Dont need to block
            return False

        active_ports = self._nas_connection_tracker.get_active_ports()
        block_value = 0
        for port in active_ports:
            priority = self._priority_list.get(str(port))
            if priority is None:
                InternalLogger.get().debug("No Priority found for port " + str(port))
            else:
                priority_block_value = self._priority_definition.get(priority)
                if priority_block_value is None:
                    InternalLogger.get().error("No Priority definition found for " + str(priority))
                else:
                    if priority_block_value > block_value:
                        block_value = priority_block_value
        InternalLogger.get().debug("Highest Priority Block Value: " + str(block_value))
        block = self._shuffling_blocked_count < block_value
        if block:
            InternalLogger.get().debug("DynPort Blocking (count = " + str(self._shuffling_blocked_count) + ")")
            self._shuffling_blocked_count = self._shuffling_blocked_count + 1
        else:
            InternalLogger.get().debug("DynPort NOT Blocking (count = " + str(self._shuffling_blocked_count) + ")")
            self._shuffling_blocked_count = 0
        return block
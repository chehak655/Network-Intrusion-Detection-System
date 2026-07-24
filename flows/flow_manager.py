from flows.flow import Flow


class FlowManager:

    def __init__(self):
        self.flows = {}

    def process_packet(
        self,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        packet_length,
        timestamp,
        tcp_flags="",
        header_length=0,
        window_size=None,
        payload_size=0
    ):

        endpoint1 = (src_ip, src_port)
        endpoint2 = (dst_ip, dst_port)

        if endpoint1 <= endpoint2:
            flow_key = (endpoint1, endpoint2, protocol)
            initiator = endpoint1
        else:
            flow_key = (endpoint2, endpoint1, protocol)
            initiator = endpoint2

        if flow_key not in self.flows:

            flow = Flow(
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol
            )

            flow.initiator = initiator

            self.flows[flow_key] = flow

        flow = self.flows[flow_key]

        current_endpoint = (src_ip, src_port)

        if current_endpoint == flow.initiator:
            direction = "forward"
        else:
            direction = "backward"

        flow.add_packet(
            packet_length,
            direction,
            timestamp,
            tcp_flags,
            header_length=header_length,
            window_size=window_size,
            payload_size=payload_size
        )

    def get_active_flows(self):
        return self.flows

    def get_completed_flows(self, timeout=30):
        """
        Return completed flows and remove them from memory.
        """

        completed = []

        keys_to_remove = []

        for key, flow in self.flows.items():

            if flow.is_finished(timeout):

                completed.append(flow)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            self.flows.pop(key, None)

        return completed

    def print_summary(self):

        print("\n" + "=" * 80)
        print("ACTIVE FLOWS")
        print("=" * 80)

        if not self.flows:
            print("No Active Flows")
            return

        for key, flow in self.flows.items():

            print(f"\nFlow : {key}")

            print(f"Duration          : {flow.duration():.2f} sec")
            print(f"Forward Packets   : {flow.forward_packets}")
            print(f"Backward Packets  : {flow.backward_packets}")
            print(f"Total Packets     : {flow.total_packets()}")
            print(f"Forward Bytes     : {flow.forward_bytes}")
            print(f"Backward Bytes    : {flow.backward_bytes}")
            print(f"Total Bytes       : {flow.total_bytes()}")
            print(f"Average Size      : {flow.average_packet_size():.2f}")
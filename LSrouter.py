
import json
import heapq

from router import Router
from packet import Packet


class LSrouter(Router):

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)

        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        self.links_info = {}
        self.link_states = {}
        self.sequence_number = 0

        self.forwarding_table = {}

        self.link_states[self.addr] = (0, {})

    def _encode_addr(self, addr):
        if isinstance(addr, bytes):
            return addr.decode("utf-8")
        return str(addr)

    def _decode_addr(self, addr):
        if isinstance(self.addr, bytes):
            return addr.encode("utf-8")
        return addr

    def _make_lsp(self):
        links = {}

        for neighbor, cost in self.links_info.values():
            links[self._encode_addr(neighbor)] = cost

        message = {
            "origin": self._encode_addr(self.addr),
            "sequence": self.sequence_number,
            "links": links
        }

        return json.dumps(message)

    def _send_lsp(self, content, exclude_port=None):
        for port, (neighbor, cost) in self.links_info.items():
            if port == exclude_port:
                continue

            packet = Packet(
                Packet.ROUTING,
                self.addr,
                neighbor,
                content
            )

            self.send(port, packet)

    def _broadcast_own_lsp(self):
        content = self._make_lsp()
        self._send_lsp(content)

    def _update_own_lsp(self):
        self.sequence_number += 1

        links = {}

        for neighbor, cost in self.links_info.values():
            links[neighbor] = cost

        self.link_states[self.addr] = (
            self.sequence_number,
            links
        )

        self._recompute_routes()
        self._broadcast_own_lsp()

    def _recompute_routes(self):
        distances = {self.addr: 0}
        next_hops = {self.addr: None}

        queue = [(0, self.addr)]

        while queue:
            current_distance, current = heapq.heappop(queue)

            if current_distance != distances.get(current):
                continue

            state = self.link_states.get(current)

            if state is None:
                continue

            sequence, neighbors = state

            for neighbor, cost in neighbors.items():
                try:
                    cost = float(cost)
                except (ValueError, TypeError):
                    continue

                if cost < 0:
                    continue

                new_distance = current_distance + cost

                if new_distance < distances.get(neighbor, float("inf")):
                    distances[neighbor] = new_distance

                    if current == self.addr:
                        next_hops[neighbor] = neighbor
                    else:
                        next_hops[neighbor] = next_hops[current]

                    heapq.heappush(
                        queue,
                        (new_distance, neighbor)
                    )

        new_table = {}

        for destination, next_hop in next_hops.items():
            if destination == self.addr:
                continue

            for port, (neighbor, cost) in self.links_info.items():
                if neighbor == next_hop:
                    new_table[destination] = port
                    break

        self.forwarding_table = new_table

    def handle_packet(self, port, packet):

        if packet.is_traceroute:
            out_port = self.forwarding_table.get(packet.dst_addr)

            if out_port is not None:
                self.send(out_port, packet)

            return

        if not packet.is_routing:
            return

        if port not in self.links_info:
            return

        immediate_neighbor = self.links_info[port][0]

        if packet.src_addr != immediate_neighbor:
            return

        try:
            message = json.loads(packet.content)

            origin = self._decode_addr(message["origin"])
            sequence = int(message["sequence"])

            links = {}

            for neighbor, cost in message["links"].items():
                links[self._decode_addr(neighbor)] = cost

        except (ValueError, TypeError, KeyError):
            return

        if origin == self.addr:
            return

        old_state = self.link_states.get(origin)

        if old_state is not None:
            old_sequence = old_state[0]

            if sequence <= old_sequence:
                return

        self.link_states[origin] = (sequence, links)

        self._recompute_routes()

        # Flood the new LSP to all neighbors except the sender.
        self._send_lsp(packet.content, exclude_port=port)

    def handle_new_link(self, port, endpoint, cost):
        self.links_info[port] = (endpoint, cost)

        self._update_own_lsp()

    def handle_remove_link(self, port):
        if port in self.links_info:
            del self.links_info[port]

        self._update_own_lsp()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_own_lsp()

    def __repr__(self):
        return "LSrouter(addr={}, forwarding={})".format(
            self.addr,
            self.forwarding_table
        )

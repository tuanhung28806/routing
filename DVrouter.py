import json
from router import Router
from packet import Packet


class DVrouter(Router):

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)

        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.infinity = 16

        self.links_info = {}
        self.neighbor_vectors = {}

        self.distance_vector = {self.addr: 0}
        self.forwarding_table = {self.addr: None}

    def encode_addr(self, addr):
        if isinstance(addr, bytes):
            return addr.decode("utf-8")
        return str(addr)

    def decode_addr(self, addr):
        if isinstance(self.addr, bytes):
            return addr.encode("utf-8")
        return addr

    def recompute_routes(self):
        distances = {self.addr: 0}
        forwarding = {self.addr: None}

        for port, (neighbor, cost) in self.links_info.items():
            cost = int(cost)

            if cost >= self.infinity:
                continue

            if cost < distances.get(neighbor, self.infinity):
                distances[neighbor] = cost
                forwarding[neighbor] = port

            vector = self.neighbor_vectors.get(neighbor, {})

            for destination, neighbor_cost in vector.items():
                if destination == self.addr:
                    continue

                total_cost = cost + int(neighbor_cost)

                if total_cost >= self.infinity:
                    continue

                if total_cost < distances.get(destination, self.infinity):
                    distances[destination] = total_cost
                    forwarding[destination] = port

        changed = (
            distances != self.distance_vector
            or forwarding != self.forwarding_table
        )

        self.distance_vector = distances
        self.forwarding_table = forwarding

        return changed

    def broadcast(self):
        for port, (neighbor, cost) in self.links_info.items():
            vector = {}

            for destination, distance in self.distance_vector.items():
                if self.forwarding_table.get(destination) == port:
                    distance = self.infinity

                vector[self.encode_addr(destination)] = distance

            packet = Packet(
                Packet.ROUTING,
                self.addr,
                neighbor,
                json.dumps(vector)
            )

            self.send(port, packet)

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

        neighbor = self.links_info[port][0]

        if packet.src_addr != neighbor:
            return

        try:
            received = json.loads(packet.content)
        except (ValueError, TypeError):
            return

        vector = {}

        for destination, distance in received.items():
            try:
                vector[self.decode_addr(destination)] = int(distance)
            except (ValueError, TypeError):
                continue

        self.neighbor_vectors[neighbor] = vector

        if self.recompute_routes():
            self.broadcast()

    def handle_new_link(self, port, endpoint, cost):
        self.links_info[port] = (endpoint, cost)

        self.neighbor_vectors.pop(endpoint, None)

        self.recompute_routes()
        self.broadcast()

    def handle_remove_link(self, port):
        if port in self.links_info:
            endpoint, cost = self.links_info.pop(port)

            if not any(
                neighbor == endpoint
                for neighbor, link_cost in self.links_info.values()
            ):
                self.neighbor_vectors.pop(endpoint, None)

        self.recompute_routes()
        self.broadcast()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.broadcast()

    def __repr__(self):
        return "DVrouter(addr={}, vector={})".format(
            self.addr,
            self.distance_vector
        )

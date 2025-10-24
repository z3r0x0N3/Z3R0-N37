
from src.crypto.utils import digital_shift_cipher, hash_data

class ProxyChain:
    """Manages the chain of proxy nodes."""

    def __init__(self, node_configs: dict, node_order: list):
        """Initializes the ProxyChain with node configurations and order."""
        self.node_configs = node_configs
        self.node_order = node_order

    def process_data(self, data: bytes) -> bytes:
        """Processes data through the proxy chain."""
        processed_data = data
        for node_id in self.node_order:
            config = self.node_configs[node_id]
            shift = sum(ord(ch) for ch in config["keyword"])
            shifted = digital_shift_cipher(processed_data, shift)
            processed_data = hash_data(shifted, config["hashing_algorithm"])
        return processed_data

    def get_node_configs(self) -> dict:
        """Returns the current configuration of all nodes in the chain."""
        return self.node_configs

    def update_node_configs(self, new_node_configs: dict):
        """Updates the configuration of nodes in the chain."""
        self.node_configs.update(new_node_configs)

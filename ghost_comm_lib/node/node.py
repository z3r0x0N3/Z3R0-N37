import json
import threading
import time
from typing import Optional, Tuple

import pgpy
from stem.control import Controller

from src.crypto.utils import (
    decrypt_pgp,
    digital_shift_cipher,
    encrypt_pgp,
    generate_pgp_key,
    hash_data,
)
from src.network.server import Server


class Node:
    """Distributed node that participates in the proxy chain."""

    def __init__(
        self,
        node_id: str,
        keyword: str,
        hashing_algorithm: str,
        host: str = "127.0.0.1",
        port: int = 0,
        tor_control_port: int = 9051,
        tor_control_password: Optional[str] = None,
        pgp_key_passphrase: Optional[str] = None,
    ):
        self.node_id = node_id
        self.keyword = keyword
        self.hashing_algorithm = hashing_algorithm
        self.host = host
        self.port = port
        self.tor_control_port = tor_control_port
        self.tor_control_password = tor_control_password
        self.pgp_key_passphrase = pgp_key_passphrase

        self.server: Optional[Server] = None
        self.server_thread: Optional[threading.Thread] = None
        self.running = False

        self.tor_controller: Optional[Controller] = None
        self.hidden_service_id: Optional[str] = None
        self.onion_address: Optional[str] = None

        self.pgp_key, self.pgp_pubkey = self._generate_pgp_keypair()
        self._connect_to_tor_controller()

    # ------------------------------------------------------------------ PGP --
    def _generate_pgp_keypair(self) -> Tuple[pgpy.PGPKey, pgpy.PGPKey]:
        name = f"Node {self.node_id}"
        email = f"{self.node_id}@ghostcomm.onion"
        key, pubkey = generate_pgp_key(name, email)
        return key, pubkey

    # ------------------------------------------------------------------- Tor --
    def _connect_to_tor_controller(self) -> None:
        try:
            self.tor_controller = Controller.from_port(port=self.tor_control_port)
            if self.tor_control_password:
                self.tor_controller.authenticate(password=self.tor_control_password)
            else:
                self.tor_controller.authenticate()
            print(f"Node {self.node_id}: Connected to Tor controller on port {self.tor_control_port}.")
        except Exception as exc:
            print(
                f"Node {self.node_id}: Warning: unable to connect to Tor control port {self.tor_control_port}: {exc}. "
                "Operating without onion service."
            )
            self.tor_controller = None

    def _create_ephemeral_service(
        self,
        local_port: int,
        await_publication: bool = True,
        publish_timeout: float = 20.0,
    ) -> Optional[str]:
        if not self.tor_controller:
            return None

        try:
            service = self.tor_controller.create_ephemeral_hidden_service(
                {80: local_port},
                key_type="NEW",
                key_content="ED25519-V3",
                await_publication=await_publication,
            )
            service_id = service.service_id
            onion = f"{service_id}.onion"

            if not await_publication:
                deadline = time.time() + publish_timeout
                published = False
                while time.time() < deadline:
                    info = self.tor_controller.get_info("onions/current", "")
                    if service_id in info:
                        published = True
                        break
                    time.sleep(0.25)
                if not published:
                    self.tor_controller.remove_ephemeral_hidden_service(service_id)
                    print(
                        f"Node {self.node_id}: Hidden service {onion} failed to publish within {publish_timeout}s."
                    )
                    return None

            self.hidden_service_id = service_id
            self.onion_address = onion
            print(f"Node {self.node_id}: Ephemeral hidden service published at {onion} (local {local_port}).")
            return onion
        except Exception as exc:
            print(f"Node {self.node_id}: Error creating hidden service on port {local_port}: {exc}")
            return None

    def _remove_ephemeral_service(self) -> None:
        if not self.tor_controller or not self.hidden_service_id:
            return
        try:
            try:
                self.tor_controller.remove_ephemeral_hidden_service(self.hidden_service_id)
            except AttributeError:
                self.tor_controller.remove_hidden_service(self.hidden_service_id)
            print(f"Node {self.node_id}: Removed hidden service {self.hidden_service_id}.onion.")
        except Exception as exc:
            print(f"Node {self.node_id}: Warning: failed to remove hidden service {self.hidden_service_id}: {exc}")
        finally:
            self.hidden_service_id = None
            self.onion_address = None

    # --------------------------------------------------------------- Runtime --
    def start_server(self) -> None:
        if self.running:
            return

        self.server = Server(self.host, self.port, self.handle_incoming_data)
        self.running = True

        def _serve():
            try:
                self.server.serve_forever()
            finally:
                self.running = False

        self.server_thread = threading.Thread(target=_serve, daemon=True)
        self.server_thread.start()

        # wait for server to bind so the real port is known
        while self.server.port == 0:
            time.sleep(0.05)

        self.port = self.server.port

        if self.tor_controller:
            self._create_ephemeral_service(self.port)

    def stop_server(self) -> None:
        self.running = False
        if self.server:
            self.server.stop()
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2)
        self._remove_ephemeral_service()
        if self.tor_controller:
            try:
                self.tor_controller.close()
            except Exception:
                pass

    # ----------------------------------------------------------- Data plane --
    def handle_incoming_data(self, data: bytes) -> bytes:
        try:
            request_payload = json.loads(data.decode("utf-8"))
            encrypted_data_for_this_node_hex = request_payload["encrypted_data"]
            next_hop_onion = request_payload.get("next_hop_onion")
            next_hop_pubkey_pem = request_payload.get("next_hop_pubkey")
            final_destination = request_payload.get("final_destination")

            encrypted_blob = bytes.fromhex(encrypted_data_for_this_node_hex)
            decrypted_layer = decrypt_pgp(encrypted_blob, self.pgp_key)
            layer_payload = json.loads(decrypted_layer.decode("utf-8"))
            original_data = bytes.fromhex(layer_payload["original_data"])

            processed_data = self.process_data(original_data)

            if next_hop_onion and next_hop_pubkey_pem:
                next_hop_pubkey, _ = pgpy.PGPKey.from_blob(next_hop_pubkey_pem.encode("utf-8"))
                data_for_next_hop = {
                    "original_data": processed_data.hex(),
                    "next_hop_onion": next_hop_onion,
                    "next_hop_pubkey": next_hop_pubkey_pem,
                    "final_destination": final_destination,
                }
                encrypted_next_blob = encrypt_pgp(json.dumps(data_for_next_hop).encode("utf-8"), next_hop_pubkey)
                print(f"Node {self.node_id}: Forwarding to next hop {next_hop_onion}.")
                return json.dumps(
                    {
                        "status": "forwarded",
                        "encrypted_data": encrypted_next_blob.hex(),
                        "next_hop_onion": next_hop_onion,
                        "final_destination": final_destination,
                    }
                ).encode("utf-8")

            if final_destination:
                print(f"Node {self.node_id}: Final hop reached for {final_destination}.")
            else:
                print(f"Node {self.node_id}: Final hop reached (no destination set).")

            return json.dumps({"status": "final_processed", "data": processed_data.hex()}).encode("utf-8")
        except Exception as exc:
            print(f"Node {self.node_id}: Error handling data: {exc}")
            return json.dumps({"status": "error", "message": str(exc)}).encode("utf-8")

    def process_data(self, data: bytes) -> bytes:
        shift = self.get_keyword_shift()
        shifted = digital_shift_cipher(data, shift)
        return hash_data(shifted, self.hashing_algorithm)

    # -------------------------------------------------------- Config update --
    def get_keyword_shift(self) -> int:
        return sum(ord(ch) for ch in self.keyword)

    def set_new_config(self, keyword: str, hashing_algorithm: str) -> None:
        self.keyword = keyword
        self.hashing_algorithm = hashing_algorithm

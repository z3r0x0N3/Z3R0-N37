# src/primary_node/primary_node.py
import json
import mimetypes
import os
import random
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import pgpy
import socks

from stem.control import Controller
from src.crypto.utils import generate_aes_key, encrypt_aes, encrypt_pgp
from src.network.server import Server
from src.network.proxy_chain import ProxyChain
from src.node.node import Node


class PrimaryNode:
    """Primary node that creates 6 fresh ephemeral .onion services each lock-cycle."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8000,
        tor_control_port: int = 9051,
        tor_control_password: str = None,
        tor_socks_host: str = "127.0.0.1",
        tor_socks_port: int = 9050,
        payload_pubkey_path: str | None = None,
        ui_html_path: str | Path | None = None,
    ):
        self.host = host
        self.port = port
        self.node_keywords = [f"keyword_{i}" for i in range(8)]
        self.hashing_algorithms = ["sha256", "sha512", "sha3_256"]
        self.project_root = Path(__file__).resolve().parents[2]

        # initial proxy chain configuration (will be replaced on first lock cycle)
        self.proxy_chain_config = self.generate_proxy_chain_config()
        self.proxy_chain = ProxyChain(self.proxy_chain_config["node_configs"], self.proxy_chain_config["node_order"])

        # server that receives client requests (assumes Server accepts host, port, handler)
        self.server = Server(self.host, self.port, self.handle_client_request)
        self.server_thread: Optional[threading.Thread] = None

        # threading / runtime control
        self.lock_cycle_thread = None
        self.running = False

        # Tor controller and ephemeral hidden services bookkeeping
        self.tor_control_port = tor_control_port
        self.tor_control_password = tor_control_password
        self.tor_controller: Controller | None = None
        # self.hidden_services maps service_id -> onion_addr (string)
        self.hidden_services: Dict[str, str] = {}
        self.distributed_nodes: Dict[str, Node] = {}
        self.onion_address: Optional[str] = None
        self.tor_socks_host = tor_socks_host
        self.tor_socks_port = tor_socks_port
        default_pubkey_path = Path(payload_pubkey_path or os.path.join(os.path.expanduser("~"), ".AUTH", "Z3R0-public-key.asc"))
        self.payload_pubkey_path = default_pubkey_path.expanduser()
        self.latest_payload: Optional[Dict[str, str]] = None
        self._payload_pubkey_warning_logged = False
        self.ui_html_path = self._resolve_ui_html_path(ui_html_path)
        self.ui_root_dir = self.ui_html_path.parent.resolve() if self.ui_html_path else None
        self._ui_html_warning_logged = False

        # attempt to connect to Tor controller at init
        self._connect_to_tor_controller()

    # -------------------------- Tor helper methods --------------------------
    def _connect_to_tor_controller(self) -> None:
        """Connect to local Tor control port (9051 by default)."""
        try:
            self.tor_controller = Controller.from_port(port=self.tor_control_port)
            if self.tor_control_password:
                self.tor_controller.authenticate(password=self.tor_control_password)
            else:
                self.tor_controller.authenticate()  # cookie or no-auth fallback
            print("PrimaryNode: Connected to Tor controller.")
        except Exception as e:
            print(f"PrimaryNode: Warning: Could not connect to Tor controller on port {self.tor_control_port}: {e}. Tor functionality will be unavailable.")
            self.tor_controller = None

    def _create_ephemeral_service(self, local_port: int, await_publication: bool = True, publish_timeout: float = 20.0) -> Tuple[str, str] | None:
        """
        Create single ephemeral hidden service mapping Tor port 80 -> local_port.
        Returns (onion_addr, service_id) on success, or None on failure.
        """
        if not self.tor_controller:
            return None

        try:
            service = self.tor_controller.create_ephemeral_hidden_service(
                {80: local_port},
                key_type="NEW",
                key_content="ED25519-V3",
                await_publication=await_publication
            )

            service_id = service.service_id
            onion_addr = f"{service_id}.onion"

            if not await_publication:
                deadline = time.time() + publish_timeout
                published = False
                while time.time() < deadline:
                    try:
                        info = (self.tor_controller.get_info("onions/current") or "")
                        if service_id in info:
                            published = True
                            break
                    except Exception:
                        pass
                    time.sleep(0.3)
                if not published:
                    try:
                        self.tor_controller.remove_ephemeral_hidden_service(service_id)
                    except Exception:
                        pass
                    print(f"PrimaryNode: Error: ephemeral onion {onion_addr} did not publish within {publish_timeout}s")
                    return None

            # record
            self.hidden_services[service_id] = onion_addr
            print(f"PrimaryNode: Created ephemeral hidden service: {onion_addr} -> local port {local_port}")
            return onion_addr, service_id

        except Exception as e:
            print(f"PrimaryNode: Error creating ephemeral hidden service (local_port={local_port}): {e}")
            return None

    def _remove_ephemeral_service(self, service_id: str) -> None:
        """Remove ephemeral hidden service by service_id (best-effort)."""
        if not self.tor_controller:
            return
        try:
            # stem provides remove_ephemeral_hidden_service in modern versions
            # if not present, fallback to remove_hidden_service (older name)
            try:
                self.tor_controller.remove_ephemeral_hidden_service(service_id)
            except AttributeError:
                # older stem naming
                self.tor_controller.remove_hidden_service(service_id)
            print(f"PrimaryNode: Removed ephemeral hidden service: {service_id}.onion")
        except Exception as e:
            print(f"PrimaryNode: Warning: could not remove ephemeral hidden service {service_id}: {e}")
        finally:
            self.hidden_services.pop(service_id, None)

    def _resolve_ui_html_path(self, ui_html_path: str | Path | None) -> Optional[Path]:
        """Determine which UI HTML file to serve for GET / requests."""
        candidates: list[Path] = []

        if ui_html_path:
            candidates.append(Path(ui_html_path).expanduser())

        env_path = os.environ.get("GHOST_COMM_PRIMARY_UI")
        if env_path:
            env_candidate = Path(env_path).expanduser()
            if env_candidate not in candidates:
                candidates.append(env_candidate)

        default_external = Path(os.path.expanduser("~/projects/botnet/WEB-GUI/GUI-index.html"))
        if default_external not in candidates:
            candidates.append(default_external)

        default_internal = self.project_root / "GUI-index.html"
        if default_internal not in candidates:
            candidates.append(default_internal)

        for candidate in candidates:
            if candidate.is_dir():
                for default_name in ("index.html", "GUI-index.html"):
                    default_candidate = candidate / default_name
                    if default_candidate.is_file():
                        resolved = default_candidate.resolve()
                        print(f"PrimaryNode: Serving UI from {resolved}")
                        return resolved
                continue
            if candidate.is_file():
                resolved = candidate.resolve()
                print(f"PrimaryNode: Serving UI from {resolved}")
                return resolved

        if candidates:
            print("PrimaryNode: Warning: no UI HTML file found in candidates: " + ", ".join(str(path) for path in candidates))

        return None

    def _safe_ui_path(self, relative_path: str) -> Optional[Path]:
        """Resolve UI asset path without allowing directory traversal."""
        if not self.ui_root_dir:
            return None
        base = self.ui_root_dir
        candidate = (base / relative_path).resolve()
        if base == candidate or base in candidate.parents:
            return candidate
        return None

    def _get_ui_asset(self, request_path: str) -> Optional[tuple[bytes, str]]:
        """Return bytes and content-type for the requested UI asset, if available."""
        if not self.ui_html_path:
            return None

        path_only = request_path.split("?", 1)[0].split("#", 1)[0]
        if path_only in ("", "/", "/index.html"):
            html_body = self._load_ui_html()
            if html_body is None:
                return None
            return html_body, "text/html; charset=utf-8"

        relative_path = path_only.lstrip("/")
        if not relative_path:
            html_body = self._load_ui_html()
            if html_body is None:
                return None
            return html_body, "text/html; charset=utf-8"

        if relative_path.endswith("/"):
            relative_path = relative_path.rstrip("/") + "/index.html"

        safe_path = self._safe_ui_path(relative_path)
        if not safe_path or not safe_path.is_file():
            # If the target is a directory, try default index files.
            if safe_path and safe_path.is_dir():
                for default_name in ("index.html", "GUI-index.html"):
                    default_path = safe_path / default_name
                    if default_path.is_file():
                        safe_path = default_path
                        break
                else:
                    return None
            else:
                # Allow implicit .html extension lookup.
                html_candidate = self._safe_ui_path(relative_path + ".html")
                if html_candidate and html_candidate.is_file():
                    safe_path = html_candidate
                else:
                    return None

        try:
            data = safe_path.read_bytes()
        except OSError as exc:
            print(f"PrimaryNode: Warning: could not read UI asset {safe_path}: {exc}")
            return None

        content_type = mimetypes.guess_type(str(safe_path))[0] or "application/octet-stream"
        if content_type == "text/html":
            content_type = "text/html; charset=utf-8"
        elif content_type == "text/css":
            content_type = "text/css; charset=utf-8"

        return data, content_type

    def _load_ui_html(self) -> Optional[bytes]:
        """Read the UI HTML content from disk."""
        if not self.ui_html_path:
            return None
        try:
            data = self.ui_html_path.read_bytes()
            self._ui_html_warning_logged = False
            return data
        except OSError as exc:
            if not self._ui_html_warning_logged:
                print(f"PrimaryNode: Warning: could not read UI HTML at {self.ui_html_path}: {exc}")
                self._ui_html_warning_logged = True
            return None

    def _load_payload_pubkey(self) -> Optional[str]:
        """Read the public key used to request payloads, logging warnings once."""
        try:
            key_text = self.payload_pubkey_path.read_text(encoding="utf-8")
            self._payload_pubkey_warning_logged = False
            return key_text
        except FileNotFoundError:
            if not self._payload_pubkey_warning_logged:
                print(f"PrimaryNode: Warning: payload public key not found at {self.payload_pubkey_path}")
                self._payload_pubkey_warning_logged = True
            return None
        except OSError as exc:
            if not self._payload_pubkey_warning_logged:
                print(f"PrimaryNode: Warning: could not read payload public key ({exc})")
                self._payload_pubkey_warning_logged = True
            return None

    def _retrieve_payload_via_onion(self) -> bool:
        """
        Fetch the latest payload from the primary node's own onion endpoint, if available.
        Stores the JSON response in self.latest_payload.
        """
        if not self.onion_address:
            return False

        pubkey_text = self._load_payload_pubkey()
        if not pubkey_text:
            return False

        request_body = json.dumps({
            "type": "get_payload",
            "pub_key": pubkey_text,
        }).encode("utf-8")

        host = self.onion_address
        request_lines = [
            "POST /payload HTTP/1.1",
            f"Host: {host}",
            "Content-Type: application/json",
            f"Content-Length: {len(request_body)}",
            "Connection: close",
            "",
            "",
        ]
        request_bytes = "\r\n".join(request_lines).encode("utf-8") + request_body

        sock: Optional[socks.socksocket] = None
        try:
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, self.tor_socks_host, self.tor_socks_port, rdns=True)
            sock.settimeout(30)
            sock.connect((host, 80))
            sock.sendall(request_bytes)

            response_chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_chunks.append(chunk)
            response_data = b"".join(response_chunks)
        except Exception as exc:
            print(f"PrimaryNode: Warning: failed to retrieve payload via onion {host}: {exc}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        header_bytes, sep, body = response_data.partition(b"\r\n\r\n")
        if not sep:
            print("PrimaryNode: Warning: invalid HTTP response when retrieving payload via onion.")
            return False

        try:
            status_line = header_bytes.decode("iso-8859-1").splitlines()[0]
            status_code = int(status_line.split(" ", 2)[1])
        except Exception:
            print("PrimaryNode: Warning: could not parse status line from payload response.")
            return False

        if status_code != 200:
            preview = body[:160].decode("utf-8", errors="replace")
            print(f"PrimaryNode: Warning: payload endpoint returned status {status_code}. Body preview: {preview}")
            return False

        try:
            payload_json = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            print(f"PrimaryNode: Warning: could not decode payload JSON: {exc}")
            return False

        self.latest_payload = payload_json
        print("PrimaryNode: Retrieved lock-cycle payload via onion.")
        return True

    def _run_payload_pipeline(self, endpoint: str) -> None:
        """Invoke external helper scripts to fetch/decrypt payload and persist JSON."""
        get_script = self.project_root / "get_primary_payload.sh"
        decrypt_script = self.project_root / "decrypt_primary_payload.sh"
        target_path = Path.home() / ".AUTH" / "Network_Access_Payload.json"

        if not get_script.exists() or not decrypt_script.exists():
            return

        target_path.parent.mkdir(parents=True, exist_ok=True)

        payload_cache = self.project_root / "payload.json"

        command = (
            f'"{get_script}" "{endpoint}" > "{payload_cache}" && '
            f'bash "{decrypt_script}" "{payload_cache}" > "{target_path}"'
        )

        env = os.environ.copy()
        env.setdefault("TOR_SOCKS_HOST", str(self.tor_socks_host))
        env.setdefault("TOR_SOCKS_PORT", str(self.tor_socks_port))
        if "GPG_TTY" not in env:
            try:
                if os.isatty(0):
                    env["GPG_TTY"] = os.ttyname(0)
            except OSError:
                pass

        try:
            subprocess.run(
                ["bash", "-lc", command],
                check=True,
                cwd=str(self.project_root),
                env=env,
            )
            print(f"PrimaryNode: Updated decrypted payload at {target_path}")
        except subprocess.CalledProcessError as exc:
            print(f"PrimaryNode: Warning: failed to update decrypted payload via helper scripts: {exc}")

    # -------------------------- Lock-cycle onion creation --------------------------
    def create_lock_cycle_onions(self, count: int = 6, local_port: int | None = None, publish_timeout: float = 20.0) -> Dict[str, Tuple[str, str]]:
        """
        Create `count` ephemeral .onion services for distributed nodes and update self.proxy_chain_config.

        Returns mapping { node_id: (onion_address, service_id) } for successfully created onions.
        On failure (Tor not connected) returns {}.
        """
        if local_port is None:
            local_port = self.port # This will be the PrimaryNode's port for its own onion service

        if not self.tor_controller:
            print("PrimaryNode: Tor controller not connected — cannot create onions.")
            return {}

        # 1) Stop and remove previous distributed nodes and their services
        if self.distributed_nodes:
            for node_id, node_instance in list(self.distributed_nodes.items()):
                try:
                    node_instance.stop_server()
                except Exception as e:
                    print(f"PrimaryNode: Warning stopping old distributed node {node_id}: {e}")
            self.distributed_nodes = {}

        # 2) Create new distributed Node instances and their ephemeral services
        created_node_info: Dict[str, Dict[str, str]] = {}
        node_ids = [f"node_{i}" for i in range(count)]
        random.shuffle(node_ids)

        for node_id in node_ids:
            # Create a new Node instance
            # We pass port=0 so the OS assigns a free port for the Node's server
            node_instance = Node(
                node_id=node_id,
                keyword=random.choice(self.node_keywords),
                hashing_algorithm=random.choice(self.hashing_algorithms),
                port=0, # Let OS assign a free port
                tor_control_port=self.tor_control_port,
                tor_control_password=self.tor_control_password
            )
            self.distributed_nodes[node_id] = node_instance

            # Start the Node's server and its hidden service
            node_instance.start_server()
            time.sleep(0.5) # Give the node's server and onion service a moment to start

            if node_instance.onion_address and node_instance.pgp_pubkey:
                created_node_info[node_id] = {
                    "onion_address": node_instance.onion_address,
                    "pgp_pubkey": str(node_instance.pgp_pubkey) # Convert PGPKey object to string for serialization
                }
            else:
                print(f"PrimaryNode: Failed to create ephemeral onion or get pubkey for distributed node {node_id}; continuing")
                # Clean up the failed node
                node_instance.stop_server()
                self.distributed_nodes.pop(node_id)

        # 3) Build node_configs for proxy chain based on created distributed nodes
        node_configs: Dict[str, Dict[str, str]] = {}
        for node_id, info in created_node_info.items():
            node_configs[node_id] = {
                "onion_address": info["onion_address"],
                "pgp_pubkey": info["pgp_pubkey"],
                "keyword": self.distributed_nodes[node_id].keyword, # Get keyword from the actual node instance
                "hashing_algorithm": self.distributed_nodes[node_id].hashing_algorithm # Get hashing_algorithm from the actual node instance
            }

        # If some failed and we need to preserve chain length, add placeholders (though ideally we want all nodes to start)
        if len(created_node_info) < count:
            print(f"PrimaryNode: Warning: Only {len(created_node_info)} out of {count} distributed nodes started successfully.")

        # final node order: shuffle to avoid predictable ordering
        final_node_order = list(node_configs.keys())
        random.shuffle(final_node_order)

        # update proxy_chain_config
        self.proxy_chain_config = {
            "node_order": final_node_order,
            "node_configs": node_configs
        }

        # The primary_node_url will now be the onion address of the PrimaryNode itself, if it has one.
        # This is for the client to initially connect to the PrimaryNode to get the payload.
        if self.onion_address:
            self.proxy_chain_config["primary_node_url"] = self.onion_address
        else:
            self.proxy_chain_config["primary_node_url"] = f"{self.host}:{self.port}" # Fallback to direct address

        # Rebuild proxy chain (this will now be a logical chain of the distributed nodes' info)
        # The ProxyChain class itself will need to be updated to reflect this change.
        # For now, we'll keep it as is, but it will be refactored later.
        self.proxy_chain = ProxyChain(self.proxy_chain_config["node_configs"], self.proxy_chain_config["node_order"])
        print(f"PrimaryNode: create_lock_cycle_onions: created {len(created_node_info)} distributed nodes, primary_node_url={self.proxy_chain_config['primary_node_url']}")
        # Retrieve the payload via the primary onion so we always have the latest encrypted bundle.
        self._retrieve_payload_via_onion()
        endpoint = f"http://{self.onion_address}/payload" if self.onion_address else f"http://{self.host}:{self.port}/payload"
        self._run_payload_pipeline(endpoint)
        return created_node_info

    # -------------------------- Other existing logic --------------------------
    def generate_proxy_chain_config(self) -> dict:
        """Generates a default proxy chain config used before onions exist."""
        # This method will now generate a config for the PrimaryNode's own onion service
        # and a placeholder for distributed nodes.
        config = {
            "node_order": [],
            "node_configs": {},
            "primary_node_url": f"{self.host}:{self.port}" # Default to direct address
        }
        print(f"PrimaryNode: Generated default proxy chain config: {config}")
        return config

    def get_lock_cycle_payload(self, client_pub_key_pem: bytes) -> bytes:
        """Generates and encrypts the lock-cycle payload (AES + wrap AES key with client PGP)."""
        client_pub_key, _ = pgpy.PGPKey.from_blob(client_pub_key_pem)

        payload = {
            "proxy_chain_config": self.proxy_chain_config,
            "primary_node_url": self.proxy_chain_config.get("primary_node_url", f"{self.host}:{self.port}")
        }
        payload_bytes = json.dumps(payload).encode("utf-8")

        # AES encryption for payload
        aes_key = generate_aes_key()
        encrypted_payload_aes = encrypt_aes(payload_bytes, aes_key)

        # wrap AES key with client PGP
        encrypted_aes_key_pgp = encrypt_pgp(aes_key, client_pub_key)

        return json.dumps({
            "encrypted_payload": encrypted_payload_aes.hex(),
            "encrypted_aes_key": encrypted_aes_key_pgp.hex()
        }).encode("utf-8")

    def refresh_lock_cycle(self):
        """Refresh lock-cycle: create 6 new distributed nodes and their onion services."""
        print("PrimaryNode: Refreshing lock-cycle...")

        # Create 6 fresh distributed nodes and their onion services
        self.create_lock_cycle_onions(count=6, publish_timeout=20.0)

        # after creation, self.proxy_chain_config and self.distributed_nodes are already updated
        print("PrimaryNode: Lock-cycle refreshed.")

    def _lock_cycle_worker(self):
        """Background worker that refreshes the lock-cycle periodically."""
        # First, create the initial set of distributed nodes
        self.create_lock_cycle_onions(count=6, publish_timeout=20.0)

        while self.running:
            # production: time.sleep(60)
            time.sleep(60)
            try:
                self.refresh_lock_cycle()
            except Exception as e:
                print(f"PrimaryNode: Lock-cycle worker encountered an error: {e}")

    def _http_response(self, status_code: int, reason: str, body: bytes, content_type: str = "text/plain") -> bytes:
        """Format a minimal HTTP/1.1 response."""
        headers = [
            f"HTTP/1.1 {status_code} {reason}",
            f"Content-Length: {len(body)}",
            f"Content-Type: {content_type}",
            "Connection: close",
        ]
        return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body

    def _parse_http_request(self, data: bytes) -> Optional[Dict[str, object]]:
        """
        Parse a simple HTTP request into its components.
        Supports curl-style GET/POST with Content-Length.
        """
        header_body_split = b"\r\n\r\n"
        if header_body_split in data:
            header_bytes, body = data.split(header_body_split, 1)
        elif b"\n\n" in data:
            header_bytes, body = data.split(b"\n\n", 1)
        else:
            return None

        try:
            header_text = header_bytes.decode("iso-8859-1")
        except UnicodeDecodeError:
            return None

        lines = header_text.split("\r\n")
        if len(lines) == 1:
            lines = header_text.split("\n")
        if not lines or not lines[0]:
            return None

        try:
            method, path, version = lines[0].split(" ", 2)
        except ValueError:
            return None

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        content_length = 0
        if "content-length" in headers:
            try:
                content_length = int(headers["content-length"])
            except ValueError:
                return None

        if content_length and len(body) < content_length:
            return None
        if content_length:
            body = body[:content_length]

        return {
            "method": method,
            "path": path,
            "version": version,
            "headers": headers,
            "body": body,
        }

    def handle_client_request(self, data: bytes) -> bytes:
        """Handle incoming client requests from Server."""
        if data.startswith(b"GET ") or data.startswith(b"POST "):
            http_request = self._parse_http_request(data)
            if not http_request:
                return self._http_response(
                    400,
                    "Bad Request",
                    b'{"error":"bad request"}',
                    content_type="application/json",
                )

            method = http_request["method"]
            path = str(http_request["path"]).split("?", 1)[0]
            headers = http_request["headers"]
            body = http_request["body"]

            if method == "GET" and path == "/health":
                health = {
                    "status": "ok",
                    "primary_onion": self.onion_address,
                    "port": self.port,
                    "nodes": list(self.distributed_nodes.keys()),
                }
                return self._http_response(
                    200,
                    "OK",
                    json.dumps(health).encode("utf-8"),
                    content_type="application/json",
                )

            if method == "GET":
                asset = self._get_ui_asset(path)
                if asset is not None:
                    body, content_type = asset
                    return self._http_response(
                        200,
                        "OK",
                        body,
                        content_type=content_type,
                    )
                if path in ("/", "/index.html"):
                    return self._http_response(
                        200,
                        "OK",
                        b"Ghost-Comm Primary Node Active\n",
                        content_type="text/plain",
                    )

            if method == "POST" and path == "/payload":
                content_type = headers.get("content-type", "")
                if "application/json" not in content_type:
                    return self._http_response(
                        415,
                        "Unsupported Media Type",
                        b'{"error":"expected application/json"}',
                        content_type="application/json",
                    )
                try:
                    payload_request = json.loads(body.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return self._http_response(
                        400,
                        "Bad Request",
                        b'{"error":"invalid json"}',
                        content_type="application/json",
                    )

                if payload_request.get("type") == "get_payload" and "pub_key" in payload_request:
                    client_pub_key_pem = payload_request["pub_key"].encode("utf-8")
                    response = self.get_lock_cycle_payload(client_pub_key_pem)
                    return self._http_response(
                        200,
                        "OK",
                        response,
                        content_type="application/json",
                    )
                return self._http_response(
                    400,
                    "Bad Request",
                    b'{"error":"invalid payload request"}',
                    content_type="application/json",
                )

            return self._http_response(
                404,
                "Not Found",
                b'{"error":"not found"}',
                content_type="application/json",
            )

        try:
            request = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return b"PrimaryNode: Error: Invalid JSON request"

        if request.get("type") == "get_payload":
            client_pub_key_pem = request["pub_key"].encode("utf-8")
            response = self.get_lock_cycle_payload(client_pub_key_pem)
            print(f"PrimaryNode: Sending payload to client.")
            return response
        if request.get("type") == "process_data":
            # This branch is now deprecated as clients will directly interact with distributed nodes.
            # However, for backward compatibility or direct processing by PrimaryNode, we can keep it.
            print("PrimaryNode: Received 'process_data' request. This should now go to distributed nodes.")
            # For now, we'll just return an error or a placeholder response.
            return json.dumps({"status": "error", "message": "Please use distributed nodes for data processing."}).encode("utf-8")
        return b"PrimaryNode: Error: Unknown request type"

    def start_server(self):
        """Start server and lock-cycle worker."""
        self.running = True
        # Start PrimaryNode's own server
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        while self.server.port == 0:
            time.sleep(0.05)
        self.port = self.server.port

        # Create PrimaryNode's own onion service
        if self.tor_controller:
            result = self._create_ephemeral_service(self.port)
            if result:
                onion_addr, service_id = result
                self.onion_address = onion_addr  # Store PrimaryNode's own onion address
                self._persist_onion_address(onion_addr)

        self.lock_cycle_thread = threading.Thread(target=self._lock_cycle_worker, daemon=True)
        self.lock_cycle_thread.start()
        print(f"PrimaryNode server started on {self.host}:{self.port}")

    def stop_server(self):
        """Stop server and cleanup ephemeral services."""
        self.running = False
        # Stop all distributed nodes
        if self.distributed_nodes:
            for node_id, node_instance in list(self.distributed_nodes.items()):
                try:
                    node_instance.stop_server()
                except Exception as e:
                    print(f"PrimaryNode: Warning stopping distributed node {node_id} at shutdown: {e}")
            self.distributed_nodes = {}

        # Remove PrimaryNode's own ephemeral service
        if self.tor_controller and self.hidden_services:
            for sid in list(self.hidden_services.keys()):
                try:
                    self._remove_ephemeral_service(sid)
                except Exception as e:
                    print(f"PrimaryNode: Warning removing own hidden service {sid} at shutdown: {e}")
            self.hidden_services = {}
            try:
                self.tor_controller.close()
            except Exception:
                pass
            self.tor_controller = None
        # stop server
        if self.server:
            self.server.stop()
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2)
        if self.lock_cycle_thread and self.lock_cycle_thread.is_alive():
            self.lock_cycle_thread.join(timeout=2)
        print("PrimaryNode server stopped.")

    def _persist_onion_address(self, onion_addr: str) -> None:
        env_target = os.getenv("GHOST_COMM_PRIMARY_ONION_FILE")
        targets = []
        if env_target:
            targets.append(Path(env_target).expanduser())

        control_url_path = Path.home() / "CONTROL-URL"
        targets.append(control_url_path)

        written = False
        for target_path in targets:
            try:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as fh:
                    fh.write(onion_addr + "\n")
                written = True
            except OSError as exc:
                print(f"PrimaryNode: Warning: failed to write onion address to {target_path}: {exc}")

        if not written:
            print("PrimaryNode: Warning: onion address could not be persisted to any target path.")

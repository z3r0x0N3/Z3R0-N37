import socket
import time
from typing import Optional

import socks
from socks import GeneralProxyError, ProxyConnectionError

class ClientConnection:
    """A simple TCP client connection, with optional SOCKS proxy support."""

    def __init__(
        self,
        host: str,
        port: int,
        socks_proxy_host: Optional[str] = None,
        socks_proxy_port: Optional[int] = None,
        connect_timeout: float = 10.0,
        retries: int = 5,
        retry_delay: float = 2.0,
    ):
        self.host = host
        self.port = port
        self.socks_proxy_host = socks_proxy_host
        self.socks_proxy_port = socks_proxy_port
        self.connect_timeout = connect_timeout
        self.retries = max(1, retries)
        self.retry_delay = max(0.0, retry_delay)
        self.socket: Optional[socket.socket] = None

    def _create_socket(self) -> socket.socket:
        if self.socks_proxy_host and self.socks_proxy_port:
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, self.socks_proxy_host, self.socks_proxy_port)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.connect_timeout)
        except Exception:
            # Some socket types might not support settimeout; ignore in those cases.
            pass
        return sock

    def connect(self):
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            self.socket = self._create_socket()
            try:
                self.socket.connect((self.host, self.port))
                print(f"Connected to {self.host}:{self.port}")
                return
            except (GeneralProxyError, ProxyConnectionError, socket.timeout, socket.error) as exc:
                last_exc = exc
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.socket = None

                if attempt < self.retries:
                    time.sleep(self.retry_delay * attempt)
                    continue

                raise

        if last_exc:
            raise last_exc

    def send_data(self, data: bytes) -> bytes:
        if not self.socket:
            raise RuntimeError("Connection has not been established.")

        self.socket.sendall(data)
        response = self.socket.recv(4096)
        return response

    def close(self):
        if self.socket:
            try:
                self.socket.close()
            finally:
                self.socket = None

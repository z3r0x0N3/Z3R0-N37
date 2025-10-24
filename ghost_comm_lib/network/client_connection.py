import socket
import socks

class ClientConnection:
    """A simple TCP client connection, with optional SOCKS proxy support."""

    def __init__(self, host: str, port: int, socks_proxy_host: str = None, socks_proxy_port: int = None):
        self.host = host
        self.port = port
        self.socks_proxy_host = socks_proxy_host
        self.socks_proxy_port = socks_proxy_port

        if self.socks_proxy_host and self.socks_proxy_port:
            self.socket = socks.socksocket()
            self.socket.set_proxy(socks.SOCKS5, self.socks_proxy_host, self.socks_proxy_port)
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        self.socket.connect((self.host, self.port))
        print(f"Connected to {self.host}:{self.port}")

    def send_data(self, data: bytes) -> bytes:
        self.socket.sendall(data)
        response = self.socket.recv(4096)
        return response

    def close(self):
        self.socket.close()